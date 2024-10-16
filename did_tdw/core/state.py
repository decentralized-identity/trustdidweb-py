"""DID history state handling."""

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union

import jsoncanon

from .date_utils import iso_format_datetime, make_timestamp
from .did_url import SCID_PLACEHOLDER
from .hash_utils import DEFAULT_HASH, HashInfo

AUTH_PARAMS = {"prerotation", "nextKeyHashes", "updateKeys"}


@dataclass
class DocumentMetadata:
    """Document resolution metadata."""

    created: datetime
    updated: datetime
    version_id: str
    version_number: int
    deactivated: bool = False

    def serialize(self) -> dict:
        """Serialize this value to a JSON-compatible dictionary."""
        return {
            "created": iso_format_datetime(self.created),
            "updated": iso_format_datetime(self.updated),
            "deactivated": self.deactivated,
            "versionId": self.version_id,
            "versionNumber": self.version_number,
        }


@dataclass
class DocumentState:
    """A state entry in a DID history log."""

    params: dict
    params_update: dict
    document: dict
    timestamp: datetime
    timestamp_raw: str
    version_id: str
    version_number: int
    last_version_id: str
    proofs: list[dict]

    @classmethod
    def initial(
        cls,
        params: dict,
        document: Union[str, dict],
        timestamp: Optional[Union[str, datetime]] = None,
        hash_name: Optional[str] = None,
    ):
        """Create a new initial state for a DID (version 1)."""
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
            last_version_id=SCID_PLACEHOLDER,
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id="",
            version_number=0,
            proofs=[],
        )
        hash_info = HashInfo.from_name(hash_name or DEFAULT_HASH)
        scid = genesis._generate_entry_hash(hash_info)
        genesis.version_id = scid

        doc_v1 = json.loads(document_str.replace(SCID_PLACEHOLDER, scid))

        genesis.params["scid"] = scid
        genesis.params_update["scid"] = scid
        genesis.document = doc_v1
        genesis.last_version_id = genesis.version_id
        genesis.version_id = "1-" + genesis._generate_entry_hash(hash_info)
        genesis.version_number = genesis.version_number + 1

        # ensure consistency
        genesis._check_scid_derivation()

        return genesis

    def _generate_entry_hash(self, hash_info: Optional[HashInfo] = None) -> str:
        if not hash_info:
            hash_info = self._get_hash_info()
        line = self.history_line()
        line["versionId"] = self.last_version_id
        del line["proof"]
        return hash_info.formatted_hash(_canonicalize_log_line(line))

    def _get_hash_info(self) -> HashInfo:
        if self.version_id:
            entry_hash = self.version_id.split("-", 1)[1]
        else:
            entry_hash = self.last_version_id.split("-", 1)[1]
        return HashInfo.identify_hash(entry_hash)

    def check_version_id(self):
        """Verify the versionId of this entry.

        Checks that the value is consistent with the version number
        and entry hash.
        """
        entry_hash = self._generate_entry_hash()
        if self.version_id != f"{self.version_number}-{entry_hash}":
            raise ValueError("Invalid version ID")

    def generate_next_key_hash(self, multikey: str) -> str:
        """Generate the hash value for an unrevealed multikey.

        This value may be added to the `nextKeyHashes` parameter.
        """
        hash_info = self._get_hash_info()
        return hash_info.formatted_hash(multikey.encode("utf-8"))

    def _check_scid_derivation(self):
        if self.version_number != 1:
            raise ValueError("Expected version number to be 1")
        scid = self.params.get("scid")
        if self.last_version_id != scid:
            raise ValueError("Parameter 'scid' must match last version ID")
        genesis_doc = json.loads(
            json.dumps(self.document).replace(scid, SCID_PLACEHOLDER)
        )
        if genesis_doc == self.document:
            raise ValueError("SCID not found in document")
        hash_info = self._get_hash_info()
        genesis_hash = hash_info.formatted_hash(
            _canonicalize_log_line(
                {
                    "versionId": SCID_PLACEHOLDER,
                    "versionTime": self.timestamp_raw,
                    "parameters": {**self.params, "scid": SCID_PLACEHOLDER},
                    "state": genesis_doc,
                }
            )
        )
        if genesis_hash != scid:
            raise ValueError(f"Invalid SCID derivation, expected: {genesis_hash}")

    def create_next(
        self,
        document: Optional[dict] = None,
        params_update: Optional[dict] = None,
        timestamp: Union[str, datetime, None] = None,
    ) -> "DocumentState":
        """Generate a successor document state from this state."""
        params = self.params.copy()
        if params_update:
            params.update(params_update)
        else:
            params_update = {}
        timestamp, timestamp_raw = make_timestamp(timestamp)
        document = deepcopy(self.document if document is None else document)
        ret = DocumentState(
            params=params,
            params_update=params_update,
            document=document,
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            last_version_id=self.version_id,
            version_id="",
            version_number=self.version_number + 1,
            proofs=[],
        )
        entry_hash = ret._generate_entry_hash()
        ret.version_id = f"{ret.version_number}-{entry_hash}"
        return ret

    @classmethod
    def load_history_line(
        cls, parts: list[str], prev_state: Optional["DocumentState"]
    ) -> "DocumentState":
        """Load a deserialized history line into a document state."""
        version_id: str
        version_number: int
        document: dict
        params_update: dict
        timestamp: datetime
        timestamp_raw: str
        proofs: list

        missing = {"versionId", "versionTime", "parameters", "state", "proof"}

        if not isinstance(parts, dict):
            raise ValueError("Expected object")
        for k, v in parts.items():
            if k == "versionId":
                if not isinstance(v, str):
                    raise ValueError("Expected string: versionId")
                version_id = v
                try:
                    version_number = int(v.split("-")[0])
                except ValueError as e:
                    raise ValueError("Invalid versionId") from e
                check_ver = prev_state.version_number + 1 if prev_state else 1
                if check_ver != version_number:
                    raise ValueError("Version number mismatch")

            elif k == "versionTime":
                if not isinstance(v, str):
                    raise ValueError("Expected string: versionTime")
                timestamp, timestamp_raw = make_timestamp(v)

            elif k == "parameters":
                if not isinstance(v, dict):
                    raise ValueError("Expected object: parameters")
                params_update = deepcopy(v)

            elif k == "state":
                if not isinstance(v, dict):
                    raise ValueError("Expected object: state")
                if not v.get("id"):
                    raise ValueError("Invalid document state: missing 'id'")
                document = deepcopy(v)

            elif k == "proof":
                if not isinstance(v, list):
                    raise ValueError("Expected list: proof")
                proofs = deepcopy(v)

            else:
                raise ValueError(f"Unexpected property: '{k}'")

            missing.remove(k)

        if missing:
            raise ValueError("Missing: " + (", ".join(missing)))

        old_params = prev_state.params if prev_state else {}
        params = cls._update_params(old_params, params_update)
        if old_params.get("prerotation") and "updateKeys" in params_update:
            # new update keys must match old hashes
            check_hashes = set(old_params.get("nextKeyHashes") or [])
            new_keys = params.get("updateKeys") or []
            hash_info = prev_state._get_hash_info()
            expect_hashes = set(
                hash_info.formatted_hash(new_key.encode("utf-8")) for new_key in new_keys
            )
            if expect_hashes != check_hashes:
                raise ValueError(
                    "New value for 'updateKeys' does not correspond "
                    "with 'nextKeyHashes' parameter"
                )

        last_version_id = prev_state.version_id if prev_state else params["scid"]

        if not isinstance(proofs, list) or any(
            not isinstance(prf, dict) for prf in proofs
        ):
            raise ValueError("Invalid proofs")

        state = DocumentState(
            version_id=version_id,
            version_number=version_number,
            timestamp_raw=timestamp_raw,
            timestamp=timestamp,
            params=params,
            params_update=params_update,
            document=document,
            proofs=proofs,
            last_version_id=last_version_id,
        )
        if not prev_state:
            state._check_scid_derivation()
        return state

    def history_line(self) -> dict:
        """Generate the serialized history line for this document state."""
        return {
            "versionId": self.version_id,
            "versionTime": self.timestamp_raw,
            "parameters": self.params_update,
            "state": self.document,
            "proof": self.proofs,
        }

    @property
    def document_id(self) -> str:
        """Fetch the identifier of the DID document."""
        return self.document.get("id")

    @property
    def deactivated(self) -> bool:
        """Fetch the `deactivated` flag from the parameters."""
        return bool(self.params.get("deactivated"))

    def document_copy(self) -> dict:
        """Fetch a copy of the DID document."""
        return deepcopy(self.document)

    @property
    def controllers(self) -> list[str]:
        """Fetch a list of the controllers from the DID document."""
        ctls = self.document.get("controller")
        if ctls is None:
            ctls = [self.document_id]
        elif isinstance(ctls, str):
            ctls = [ctls]
        elif not isinstance(ctls, list):
            raise ValueError("Invalid controller property")
        return ctls

    @property
    def is_auth_event(self) -> bool:
        """Determine if this document state constitutes an authorization event."""
        return not AUTH_PARAMS.isdisjoint(self.params_update.keys())

    @property
    def prerotation(self) -> bool:
        """Determine whether key prerotation is enabled for this document state."""
        return self.params.get("prerotation", False)

    @property
    def scid(self) -> str:
        """Fetch the SCID of the DID document."""
        return self.params["scid"]

    @property
    def update_keys(self) -> list[str]:
        """Fetch a list of the `updateKeys` entries from the parameters."""
        upd_keys = self.params.get("updateKeys")
        if upd_keys is not None and (
            not isinstance(upd_keys, list)
            or not all(isinstance(k, str) for k in upd_keys)
        ):
            raise ValueError("Invalid 'updateKeys' parameter")
        return upd_keys or []

    @property
    def next_key_hashes(self) -> list[str]:
        """Fetch a list of the `nextKeyHashes` entries from the parameters."""
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
            elif param == "method":
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'method' parameter: {pvalue!r}"
                    )
            elif param == "nextKeyHashes":
                if pvalue is not None and (
                    not isinstance(pvalue, list)
                    or not all(isinstance(k, str) for k in pvalue)
                ):
                    raise ValueError(
                        f"Unsupported value for 'nextKeyHashes' parameter: {pvalue!r}"
                    )
            elif param == "portable":
                if not isinstance(pvalue, bool):
                    raise ValueError(
                        f"Unsupported value for 'portable' parameter: {pvalue!r}"
                    )
                if pvalue and old_params and not old_params.get("portable"):
                    raise ValueError(
                        "Parameter 'portable' may only be enabled in the first entry"
                    )
            elif param == "prerotation":
                if pvalue not in (True, False):
                    raise ValueError(
                        f"Unsupported value for 'prerotation' parameter: {pvalue!r}"
                    )
                if old_params.get("prerotation") and not pvalue:
                    raise ValueError("Parameter 'prerotation' cannot be changed to False")
            elif param == "scid":
                if old_params:
                    raise ValueError("Parameter 'scid' cannot be updated")
                if not isinstance(pvalue, str) or not pvalue:
                    raise ValueError(
                        f"Unsupported value for 'scid' parameter: {pvalue!r}"
                    )
            elif param == "ttl":
                if not isinstance(pvalue, int) or pvalue <= 0:
                    raise ValueError(f"Unsupported value for 'ttl' parameter: {pvalue!r}")
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


def _canonicalize_log_line(line: dict) -> bytes:
    return jsoncanon.canonicalize(line)
