import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Optional, Union

import jsonpatch

from .date_utils import format_datetime, make_timestamp
from .scid import (
    PLACEHOLDER,
    derive_scid,
    format_hash,
    normalize_genesis,
    normalize_log_line,
)


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
    ):
        if "hash" in params and params["hash"] != "sha2-256":
            raise ValueError(f"Unsupported hash function: {params['hash']}")
        doc_norm = normalize_genesis(document)
        genesis_hash = format_hash(sha256(doc_norm).digest())
        scid = derive_scid(genesis_hash)
        if isinstance(document, dict):
            document = json.dumps(document)
        doc_v1 = json.loads(document.replace(PLACEHOLDER, scid))
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
            last_version_hash=genesis_hash,
            proofs=[],
        )
        ret.version_hash = ret.calculate_hash()
        return ret

    def calculate_hash(self) -> str:
        return format_hash(
            sha256(
                normalize_log_line(
                    [
                        self.last_version_hash,
                        self.version_id,
                        self.timestamp_raw,
                        self.params_update,
                        self.document_update,
                    ]
                )
            ).digest()
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

        params = prev_state.params.copy() if prev_state else {}
        for param, pvalue in params_update.items():
            if param == "method":
                # FIXME - validate method parameter
                pass
            elif param == "hash":
                if pvalue != "sha2-256":
                    raise ValueError("Unsupported hash parameter: {pvalue}")
            elif param == "scid":
                if prev_state:
                    raise ValueError("Parameter 'scid' cannot be updated")
            else:
                raise ValueError(f"Unsupported history parameter: {param}")
            if param is None:
                if param in params:
                    del params[param]
            else:
                params[param] = pvalue
        if "method" not in params or "scid" not in params:
            raise ValueError("Invalid initial parameters")

        check_ver = prev_state.version_id + 1 if prev_state else 1
        if check_ver != version_id:
            raise ValueError("Version ID mismatch")

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
            last_version_hash = format_hash(
                sha256(normalize_genesis(document, check_scid=params["scid"])).digest()
            )

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