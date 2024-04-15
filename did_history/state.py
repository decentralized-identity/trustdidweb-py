import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256, sha3_256
from typing import Callable, Optional, TypeVar, Union

import jsonpatch

from .date_utils import format_datetime, make_timestamp
from .format import (
    SCID_PLACEHOLDER,
    format_hash,
    normalize_genesis,
    normalize_log_line,
)

HashFn = TypeVar("HashFn", bound=Callable[[bytes], bytes])

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
        hash_fn = get_hash_fn(params)
        doc_norm = normalize_genesis(document)
        genesis_hash = format_hash(hash_fn(doc_norm))
        if scid_length is None:
            scid_length = MIN_SCID_LENGTH
        elif scid_length < MIN_SCID_LENGTH or scid_length > len(genesis_hash):
            raise ValueError(f"Invalid SCID length: {scid_length}")
        scid = genesis_hash[:scid_length]
        if isinstance(document, dict):
            document = json.dumps(document)
        doc_v1 = json.loads(document.replace(SCID_PLACEHOLDER, scid))
        doc_id = doc_v1.get("id")
        if not isinstance(doc_id, str):
            raise ValueError("Expected string for document id")
        if scid not in doc_id:
            raise ValueError("SCID missing from document id")

        # debug: checking the SCID derivation
        check_doc_norm = normalize_genesis(doc_v1, check_scid=scid)
        assert check_doc_norm == doc_norm

        timestamp, timestamp_raw = make_timestamp(timestamp)
        params = {**params, "scid": scid}

        ret = DocumentState(
            params=params,
            params_update=params.copy(),
            document=doc_v1,
            document_update={"value": deepcopy(doc_v1)},
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id=1,
            version_hash="",
            last_version_hash=scid,
            proofs=[],
        )
        ret.version_hash = ret.calculate_hash()
        return ret

    def calculate_hash(self) -> str:
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

    def create_next(
        self,
        document: dict,
        params_update: dict = None,
        timestamp: Union[str, datetime] = None,
    ) -> "DocumentState":
        params = self.params.copy()
        if params_update:
            params.update(params_update)
        else:
            params_update = {}
        timestamp, timestamp_raw = make_timestamp(timestamp)
        document = deepcopy(document)
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
        ret.version_hash = ret.calculate_hash()
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
            raise ValueError("Invalid history data")

        params = cls._update_params(
            prev_state.params if prev_state else {}, params_update
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

        # check SCID derivation for first version
        if prev_state:
            last_version_hash = prev_state.version_hash
        else:
            last_version_hash = params["scid"]
            if len(last_version_hash) < MIN_SCID_LENGTH:
                raise ValueError("Invalid SCID length")
            hash_fn = get_hash_fn(params)
            genesis_hash = format_hash(
                hash_fn(normalize_genesis(document, check_scid=last_version_hash))
            )
            if not genesis_hash.startswith(last_version_hash):
                raise ValueError("Invalid SCID derivation")

        timestamp, timestamp_raw = make_timestamp(timestamp_raw)

        if not isinstance(proofs, list) or any(
            not isinstance(prf, dict) for prf in proofs
        ):
            raise ValueError("Invalid proofs")

        return DocumentState(
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

    def controllers(self) -> list[str]:
        ctls = self.document.get("controller")
        if ctls is None:
            ctls = [self.document_id]
        elif isinstance(ctls, str):
            ctls = [ctls]
        elif not isinstance(ctls, list):
            raise ValueError("Invalid controller property")
        return ctls

    def authentication_keys(self) -> dict[str, dict]:
        doc_id = self.document_id
        auth_keys = {}
        vmethods = self.document.get("verificationMethod", [])
        vm_dict = {}
        if not isinstance(vmethods, list):
            raise ValueError("Invalid verificationMethod property")
        for method in vmethods:
            _ = parse_verification_method(method, doc_id, vm_dict)
        auths = self.document.get("authentication", [])
        if not isinstance(auths, list):
            raise ValueError("Invalid authentication property")
        for auth in auths:
            if isinstance(auth, str):
                if auth.startswith("#"):
                    auth = doc_id + auth
                if auth not in vm_dict:
                    raise ValueError(
                        f"Cannot resolve authentication key reference: {auth}"
                    )
            elif isinstance(auth, dict):
                auth = parse_verification_method(auth, doc_id, vm_dict)
            auth_keys[auth] = vm_dict[auth]
        return auth_keys

    @classmethod
    def _update_params(cls, old_params: dict, new_params: dict) -> dict:
        res = old_params.copy()
        for param, pvalue in new_params.items():
            if param == "deactivated":
                if pvalue not in (None, True, False):
                    raise ValueError(f"Unsupported value for 'deactivated' parameter")
            elif param == "hash":
                if pvalue is not None and pvalue not in HASH_FN_MAP:
                    raise ValueError("Unsupported 'hash' parameter: {pvalue}")
            elif param == "method":
                # FIXME - more flexible validation for method parameter?
                if pvalue != "did:tdw:1":
                    raise ValueError(f"Unsupported 'method' parameter: {pvalue}")
            elif param == "moved":
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'moved' parameter: {pvalue}"
                    )
            elif param == "scid":
                if old_params:
                    raise ValueError("Parameter 'scid' cannot be updated")
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'scid' parameter: {pvalue}"
                    )
            elif param == "ttl":
                if not isinstance(pvalue, int) or pvalue <= 0:
                    raise ValueError(f"Unsupported value for 'ttl' parameter: {pvalue}")
            else:
                raise ValueError(f"Unsupported history parameter: {param}")

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
