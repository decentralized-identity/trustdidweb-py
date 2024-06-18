import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256, sha3_256
from typing import Callable, Optional, TypeAlias, Union

import jsonpatch

from .did import SCID_PLACEHOLDER
from .date_utils import format_datetime, make_timestamp
from .format import (
    format_hash,
    normalize_log_line,
)

HashFn: TypeAlias = Callable[[bytes], bytes]

HASH_FN_MAP: dict[str, HashFn] = {
    "sha256": lambda b: sha256(b).digest(),
    "sha3-256": lambda b: sha3_256(b).digest(),
}
MIN_SCID_LENGTH: int = 28


def get_hash_fn(params: dict) -> HashFn:
    hash_name = params.get("hash")
    if hash_name is None:
        hash_name = "sha256"
    hash_f = HASH_FN_MAP.get(hash_name)
    if not hash_f:
        raise ValueError(f"Unsupported hash function: {hash_name}")
    return hash_f


@dataclass
class DocumentMetadata:
    created: datetime
    updated: datetime
    version_id: int
    deactivated: bool = False

    def serialize(self) -> dict:
        return {
            "created": format_datetime(self.created),
            "updated": format_datetime(self.updated),
            "deactivated": self.deactivated,
            "versionId": str(self.version_id),
        }


@dataclass
class DocumentState:
    params: dict
    params_update: dict
    document: dict
    document_update: dict
    timestamp: datetime
    timestamp_raw: str
    version_id: int
    version_hash: str
    last_version_hash: str
    proofs: list[dict]

    @classmethod
    def initial(
        cls,
        params: dict,
        document: Union[str, dict],
        timestamp: Optional[Union[str, datetime]] = None,
        scid_length: int = None,
    ):
        if scid_length is None:
            scid_length = MIN_SCID_LENGTH
        timestamp, timestamp_raw = make_timestamp(timestamp)

        if isinstance(document, str):
            document_str = document
            document = json.loads(document)
        else:
            document_str = json.dumps(document)

        doc_id = document.get("id")
        if not isinstance(doc_id, str):
            raise ValueError("Expected string for document id")
        if SCID_PLACEHOLDER not in doc_id:
            raise ValueError("SCID placeholder missing from document id")

        params = {**params, "scid": SCID_PLACEHOLDER}
        genesis = DocumentState(
            params=params,
            params_update=params.copy(),
            document=document,
            document_update={"value": deepcopy(document)},
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id=1,
            version_hash="",
            last_version_hash=SCID_PLACEHOLDER,
            proofs=[],
        )
        genesis_hash = genesis.generate_hash()

        if scid_length < MIN_SCID_LENGTH or scid_length > len(genesis_hash):
            raise ValueError(f"Invalid SCID length: {scid_length}")

        scid = genesis_hash[:scid_length]
        doc_v1 = json.loads(document_str.replace(SCID_PLACEHOLDER, scid))

        genesis.params["scid"] = scid
        genesis.params_update["scid"] = scid
        genesis.document = doc_v1
        genesis.document_update = {"value": deepcopy(doc_v1)}
        genesis.last_version_hash = scid
        genesis.version_hash = genesis.generate_hash()

        # ensure consistency
        genesis.check_scid_derivation()

        return genesis

    def generate_hash(self) -> str:
        hash_fn = get_hash_fn(self.params)
        return format_hash(
            hash_fn(
                normalize_log_line(
                    [
                        self.last_version_hash,
                        self.version_id,
                        self.timestamp_raw,
                        self.params_update,
                        self.document_update,
                    ]
                )
            )
        )

    def generate_next_key_hash(self, multikey: str) -> str:
        hash_fn = get_hash_fn(self.params)
        return format_hash(hash_fn(multikey.encode("utf-8")))

    def check_scid_derivation(self):
        if self.version_id != 1:
            raise ValueError("Expected versionId to be 1")
        scid = self.params.get("scid")
        if not scid or len(scid) < MIN_SCID_LENGTH:
            raise ValueError("Invalid SCID length")
        if self.last_version_hash != scid:
            raise ValueError("Parameter 'scid' must match last version hash")
        genesis_doc = json.loads(
            json.dumps(self.document).replace(scid, SCID_PLACEHOLDER)
        )
        if genesis_doc == self.document:
            raise ValueError("SCID not found in document")
        hash_fn = get_hash_fn(self.params)
        genesis_hash = format_hash(
            hash_fn(
                normalize_log_line(
                    [
                        SCID_PLACEHOLDER,
                        self.version_id,
                        self.timestamp_raw,
                        {**self.params, "scid": SCID_PLACEHOLDER},
                        {"value": genesis_doc},
                    ]
                )
            )
        )
        if not genesis_hash.startswith(scid):
            raise ValueError("Invalid SCID derivation")

    def create_next(
        self,
        document_update: dict,
        params_update: dict = None,
        timestamp: Union[str, datetime] = None,
    ) -> "DocumentState":
        params = self.params.copy()
        if params_update:
            params.update(params_update)
        else:
            params_update = {}
        timestamp, timestamp_raw = make_timestamp(timestamp)
        if document_update is None:
            document = deepcopy(self.document)
            doc_update = {"value": deepcopy(document)}
        else:
            document = deepcopy(document_update)
            doc_update = {"patch": jsonpatch.make_patch(self.document, document).patch}
        ret = DocumentState(
            params=params,
            params_update=params_update,
            document=document,
            document_update=doc_update,
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id=self.version_id + 1,
            last_version_hash=self.version_hash,
            version_hash="",
            proofs=[],
        )
        ret.version_hash = ret.generate_hash()
        return ret

    @classmethod
    def load_history_line(
        cls, parts: list[str], prev_state: Optional["DocumentState"]
    ) -> "DocumentState":
        if not isinstance(parts, list) or len(parts) != 6:
            raise ValueError("Cannot parse history")
        (version_hash, version_id, timestamp_raw, params_update, doc_update, proofs) = (
            parts
        )
        if not isinstance(params_update, dict):
            raise ValueError("Invalid history parameters")
        if not isinstance(doc_update, dict) or not ("value" in doc_update) ^ (
            "patch" in doc_update
        ):
            # FIXME allow an empty document update?
            raise ValueError("Invalid history data")

        old_params = prev_state.params if prev_state else {}
        params = cls._update_params(old_params, params_update)
        if old_params.get("prerotation") and "updateKeys" in params_update:
            # new update keys must match old hashes
            check_hashes = set(old_params.get("nextKeyHashes") or [])
            new_keys = params.get("updateKeys") or []
            hash_fn = get_hash_fn(old_params)
            expect_hashes = set(
                format_hash(hash_fn(new_key.encode("utf-8"))) for new_key in new_keys
            )
            if expect_hashes != check_hashes:
                raise ValueError(
                    "New value for 'updateKeys' does not correspond "
                    "with 'nextKeyHashes' parameter"
                )

        check_ver = prev_state.version_id + 1 if prev_state else 1
        if check_ver != version_id:
            raise ValueError("VersionId mismatch")

        if "value" in doc_update:
            document = doc_update["value"]
        else:
            if not prev_state:
                raise ValueError("Invalid initial data")
            # FIXME wrap error
            document = jsonpatch.apply_patch(prev_state.document, doc_update["patch"])

        if not isinstance(document, dict) or "id" not in document:
            raise ValueError("Invalid document state")

        if prev_state:
            last_version_hash = prev_state.version_hash
        else:
            last_version_hash = params["scid"]

        timestamp, timestamp_raw = make_timestamp(timestamp_raw)

        if not isinstance(proofs, list) or any(
            not isinstance(prf, dict) for prf in proofs
        ):
            raise ValueError("Invalid proofs")

        state = DocumentState(
            params=params,
            params_update=params_update,
            document=document,
            document_update=doc_update,
            timestamp_raw=timestamp_raw,
            timestamp=timestamp,
            version_id=version_id,
            last_version_hash=last_version_hash,
            version_hash=version_hash,
            proofs=proofs,
        )
        if not prev_state:
            state.check_scid_derivation()
        return state

    def history_line(self) -> list:
        return [
            self.version_hash,
            self.version_id,
            self.timestamp_raw,
            self.params_update,
            self.document_update,
            self.proofs,
        ]

    @property
    def document_id(self) -> str:
        return self.document.get("id")

    @property
    def deactivated(self) -> bool:
        return bool(self.params.get("deactivated"))

    def document_copy(self) -> dict:
        return deepcopy(self.document)

    @property
    def controllers(self) -> list[str]:
        ctls = self.document.get("controller")
        if ctls is None:
            ctls = [self.document_id]
        elif isinstance(ctls, str):
            ctls = [ctls]
        elif not isinstance(ctls, list):
            raise ValueError("Invalid controller property")
        return ctls

    @property
    def prerotation(self) -> bool:
        return self.params.get("prerotation", False)

    @property
    def update_keys(self) -> list[str]:
        upd_keys = self.params.get("updateKeys")
        if upd_keys is not None and (
            not isinstance(upd_keys, list)
            or not all(isinstance(k, str) for k in upd_keys)
        ):
            raise ValueError("Invalid 'updateKeys' parameter")
        return upd_keys or []

    @property
    def next_key_hashes(self) -> list[str]:
        next_keys = self.params.get("nextKeyHashes")
        if next_keys is not None and (
            not isinstance(next_keys, list)
            or not all(isinstance(k, str) for k in next_keys)
        ):
            raise ValueError("Invalid 'nextKeyHashes' parameter")
        return next_keys or []

    @classmethod
    def _update_params(cls, old_params: dict, new_params: dict) -> dict:
        res = old_params.copy()
        for param, pvalue in new_params.items():
            if param == "deactivated":
                if pvalue not in (None, True, False):
                    raise ValueError("Unsupported value for 'deactivated' parameter")
            elif param == "hash":
                if pvalue is not None and pvalue not in HASH_FN_MAP:
                    raise ValueError(f"Unsupported 'hash' parameter: {pvalue!r}")
            elif param == "method":
                # FIXME - more flexible validation for method parameter?
                if pvalue != "did:tdw:1":
                    raise ValueError(f"Unsupported 'method' parameter: {pvalue!r}")
            elif param == "moved":
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'moved' parameter: {pvalue!r}"
                    )
            elif param == "nextKeyHashes":
                if pvalue is not None and (
                    not isinstance(pvalue, list)
                    or not all(isinstance(k, str) for k in pvalue)
                ):
                    raise ValueError(
                        f"Unsupported value for 'nextKeyHashes' parameter: {pvalue!r}"
                    )
            elif param == "prerotation":
                if pvalue not in (True, False):
                    raise ValueError(
                        f"Unsupported value for 'prerotation' parameter: {pvalue!r}"
                    )
                if old_params.get("prerotation") and not pvalue:
                    raise ValueError(
                        "Parameter 'prerotation' cannot be changed to False"
                    )
            elif param == "scid":
                if old_params:
                    raise ValueError("Parameter 'scid' cannot be updated")
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'scid' parameter: {pvalue!r}"
                    )
            elif param == "ttl":
                if not isinstance(pvalue, int) or pvalue <= 0:
                    raise ValueError(
                        f"Unsupported value for 'ttl' parameter: {pvalue!r}"
                    )
            elif param == "updateKeys":
                if pvalue is not None and (
                    not isinstance(pvalue, list)
                    or not all(isinstance(k, str) for k in pvalue)
                ):
                    raise ValueError(
                        f"Unsupported value for 'updateKeys' parameter: {pvalue!r}"
                    )
            else:
                raise ValueError(f"Unsupported history parameter: {param!r}")

            if pvalue is None:
                if param in res:
                    del res[param]
            else:
                res[param] = pvalue

        if "method" not in res or "scid" not in res:
            raise ValueError("Invalid initial parameters")
        return res


def parse_verification_method(method: dict, doc_id: str, method_dict: dict) -> str:
    if not isinstance(method, dict):
        raise ValueError("invalid verification methods")
    method_id = method.get("id")
    if not isinstance(method_id, str):
        raise ValueError("invalid verification method ID")
    if method_id.startswith("#"):
        method_id = doc_id + method_id
    if method_id in method_dict:
        raise ValueError("duplicate verification method ID")
    method_dict[method_id] = method
    return method_id
