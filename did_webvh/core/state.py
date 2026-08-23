"""DID history state handling."""

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import jcs

from ..const import METHOD_NAME, METHOD_VERSION, SCID_PLACEHOLDER
from .date_utils import (
    MAX_FUTURE_SKEW,
    create_next_version_time,
    iso_format_datetime,
    make_timestamp,
)
from .hash_utils import DEFAULT_HASH, HashInfo
from .problem_details import ProblemDetails
from .proof import di_jcs_sign, di_jcs_verify, resolve_did_key
from .types import SigningKey, VerifyingKey
from .witness import WitnessRule

AUTHZ_PARAMS = {"nextKeyHashes", "updateKeys"}
DEFAULT_METHOD = f"did:{METHOD_NAME}:{METHOD_VERSION}"


class InvalidDocumentState(ValueError):
    """A `ValueError` subclass indicating an invalid document state."""

    problem_details: ProblemDetails

    def __init__(self, problem_details: ProblemDetails):
        """Initializer."""
        self.problem_details = problem_details
        super().__init__(str(problem_details))


@dataclass
class DocumentMetadata:
    """Document resolution metadata."""

    created: datetime
    updated: datetime
    scid: str
    version_id: str
    version_number: int
    version_time: datetime
    deactivated: bool = False
    portable: bool = False
    watchers: list | None = None
    witness: dict | None = None

    def serialize(self) -> dict:
        """Serialize this value to a JSON-compatible dictionary."""
        return {
            "created": iso_format_datetime(self.created),
            "updated": iso_format_datetime(self.updated),
            "deactivated": self.deactivated,
            "portable": self.portable,
            "scid": self.scid,
            "versionId": self.version_id,
            "versionNumber": self.version_number,
            "versionTime": iso_format_datetime(self.version_time),
            "watchers": self.watchers,
            "witness": self.witness,
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
    proofs: list[dict] = field(default_factory=list)
    last_key_hashes: list[str] | None = None

    @classmethod
    def initial(
        cls,
        params: dict,
        document: str | dict,
        timestamp: str | datetime | None = None,
        hash_name: str | None = None,
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
            raise ValueError("Expected string for DID document id")
        if SCID_PLACEHOLDER not in doc_id:
            raise ValueError("SCID placeholder missing from document id")

        params = params.copy()
        if "method" not in params:
            params["method"] = DEFAULT_METHOD
        if "scid" not in params:
            params["scid"] = SCID_PLACEHOLDER
        genesis = DocumentState(
            params=params,
            params_update=params.copy(),
            document=document,
            last_version_id=SCID_PLACEHOLDER,
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id="",
            version_number=0,
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
        genesis.version_number = 1

        # ensure consistency
        genesis._check_scid_derivation()

        return genesis

    def _generate_entry_hash(self, hash_info: HashInfo | None = None) -> str:
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
        """Verify the `versionId` of this entry.

        Checks that the value is consistent with the version number
        and entry hash.
        """
        entry_hash = self._generate_entry_hash()
        if self.version_id != f"{self.version_number}-{entry_hash}":
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#hash-chain-broken",
                    title="The cryptographic hash chain was broken.",
                    detail="Unexpected value for `versionId`.",
                    versionId=self.version_id,
                    versionNumber=self.version_number,
                )
            )

    def generate_next_key_hash(self, multikey: str) -> str:
        """Generate the hash value for an unrevealed multikey.

        This value may be added to the `nextKeyHashes` parameter.
        """
        hash_info = self._get_hash_info()
        return hash_info.formatted_hash(multikey.encode("utf-8"))

    def _check_genesis_entry(self):
        if "method" not in self.params:
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter("Missing 'method' parameter")
            )
        if "scid" not in self.params:
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter("Missing 'scid' parameter")
            )
        try:
            self._check_scid_derivation()
        except ValueError as err:
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#scid-verification-failed",
                    title="SCID validation failed",
                    detail=str(err),
                )
            ) from None

    def _check_scid_derivation(self):
        scid = self.params.get("scid")
        if not isinstance(scid, str):
            raise ValueError("Invalid 'scid' parameter")
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

    def _check_key_rotation(self):
        last_key_hashes = self.last_key_hashes
        # Empty list is semantically equivalent to missing (no pre-rotation commitment)
        if last_key_hashes is None or last_key_hashes == []:
            return

        if not isinstance(last_key_hashes, list) or not all(
            isinstance(k, str) for k in last_key_hashes
        ):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid value for 'nextKeyHashes', expected list of strings"
                )
            )
        update_keys = self.params_update.get("updateKeys")
        if update_keys is None:
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "'updateKeys' must be provided when 'nextKeyHashes' is non-empty"
                )
            )

        if not isinstance(update_keys, list) or not all(
            isinstance(k, str) for k in update_keys
        ):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid value for 'updateKeys', expected list of strings"
                )
            )

        # new update keys must be found in old hashes
        check_hashes = {}
        for h in last_key_hashes:
            check_hashes[h] = HashInfo.identify_hash(h)
        for new_key in update_keys:
            found = False
            for key_hash, hash_info in check_hashes.items():
                check_hash = hash_info.formatted_hash(new_key.encode("utf-8"))
                if check_hash == key_hash:
                    found = True
                    break
            if not found:
                raise InvalidDocumentState(
                    ProblemDetails.invalid_parameter(
                        f"Encoded key '{new_key}' in 'updateKeys' is not found in "
                        "previous 'nextKeyHashes' parameter"
                    )
                )

    def create_next(
        self,
        document: dict | str | None = None,
        params_update: dict | None = None,
        timestamp: str | datetime | None = None,
    ) -> "DocumentState":
        """Generate a successor document state from this state."""
        params = self.params.copy()
        if params_update:
            params.update(params_update)
        else:
            params_update = {}
        timestamp, timestamp_raw = create_next_version_time(
            self.timestamp_raw,
            timestamp,
        )
        if isinstance(document, str):
            document = json.loads(document)
        else:
            document = deepcopy(self.document if document is None else document)
        ret = DocumentState(
            params=params,
            params_update=params_update,
            document=document,
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id="",
            version_number=self.version_number + 1,
            last_version_id=self.version_id,
            last_key_hashes=self.next_key_hashes,
        )
        entry_hash = ret._generate_entry_hash()
        ret.version_id = f"{ret.version_number}-{entry_hash}"
        return ret

    @classmethod
    def load_history_json(
        cls, line: str, prev_state: Optional["DocumentState"] | None
    ) -> "DocumentState":
        """Load a serialized history line encoded as JSON."""
        try:
            parts = json.loads(line)
        except ValueError as err:
            raise InvalidDocumentState(
                ProblemDetails.invalid_log_entry(
                    f"Could not parse log entry as JSON: {str(err)}"
                )
            ) from None
        return cls.load_history_line(parts, prev_state)

    @classmethod
    def load_history_line(
        cls, parts: dict, prev_state: Optional["DocumentState"] | None
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
            raise InvalidDocumentState(
                ProblemDetails.invalid_log_entry(
                    "The log entry is not an object.",
                )
            )
        for k, v in parts.items():
            if k == "versionId":
                if not isinstance(v, str):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `versionId` property: expected string.",
                        )
                    )
                version_id = v
                try:
                    version_number = int(v.split("-")[0])
                except ValueError:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `versionId` property.",
                        )
                    ) from None
                check_ver = prev_state.version_number + 1 if prev_state else 1
                if check_ver != version_number:
                    raise InvalidDocumentState(
                        ProblemDetails(
                            type="#version-mismatch",
                            title="Invalid version number sequence.",
                            expected=check_ver,
                            found=version_number,
                        )
                    )

            elif k == "versionTime":
                if not isinstance(v, str):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `versionTime` property: expected string.",
                        )
                    )
                try:
                    timestamp, timestamp_raw = make_timestamp(v)
                except ValueError:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `versionTime` property.",
                        )
                    ) from None

            elif k == "parameters":
                if not isinstance(v, dict):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `parameters` property: expected object.",
                        )
                    )
                params_update = deepcopy(v)

            elif k == "state":
                if not isinstance(v, dict):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `state` property: expected object.",
                        )
                    )
                if not v.get("id"):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `state` property: missing document id.",
                        )
                    )
                document = deepcopy(v)

            elif k == "proof":
                if not isinstance(v, list) or any(not isinstance(prf, dict) for prf in v):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_log_entry(
                            "Invalid `proof` property: expected list of objects.",
                        )
                    )
                proofs = deepcopy(v)

            else:
                raise InvalidDocumentState(
                    ProblemDetails.invalid_log_entry(
                        f"Unexpected property: '{k}'",
                    )
                )

            missing.remove(k)

        if missing:
            raise InvalidDocumentState(
                ProblemDetails.invalid_log_entry(
                    "Missing one or more properties: " + (", ".join(missing)),
                )
            )

        old_params = prev_state.params if prev_state else {}
        params = cls._update_params(old_params, params_update)

        last_version_id = prev_state.version_id if prev_state else params["scid"]

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
            last_key_hashes=prev_state.next_key_hashes if prev_state else None,
        )

        if not prev_state:
            state._check_genesis_entry()
        state._check_key_rotation()

        return state

    def history_line(self) -> dict:
        """Generate the unserialized history line for this document state."""
        return {
            "versionId": self.version_id,
            "versionTime": self.timestamp_raw,
            "parameters": self.params_update,
            "state": self.document,
            "proof": self.proofs,
        }

    def history_json(self) -> str:
        """Generate the JSON-serialized history line for this document state."""
        return json.dumps(self.history_line())

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

    def to_did_web(self) -> dict:
        """Fetch a copy of the DID document with did web transformation."""
        document = deepcopy(self.document)
        transformed_document = json.loads(
            json.dumps(document).replace(f"did:webvh:{self.scid}:", "did:web:")
        )
        if transformed_document.get("alsoKnownAs"):
            transformed_document["alsoKnownAs"].append(self.document_id)
        else:
            transformed_document["alsoKnownAs"] = [self.document_id]
        return transformed_document

    @property
    def controllers(self) -> list[str]:
        """Fetch a list of the controllers from the DID document."""
        ctls = self.document.get("controller")
        if ctls is None:
            ctls = [self.document_id]
        elif isinstance(ctls, str):
            ctls = [ctls]
        elif not isinstance(ctls, list):
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#invalid-did-document", title="Invalid 'controller' property"
                )
            )
        return ctls

    @property
    def is_authz_event(self) -> bool:
        """Determine if this document state constitutes an authorization event."""
        return not AUTHZ_PARAMS.isdisjoint(self.params_update.keys())

    @property
    def portable(self) -> bool:
        """Fetch the `portable` flag from the parameters."""
        return bool(self.params.get("portable"))

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
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid 'updateKeys' parameter: expected list of strings"
                )
            )
        return upd_keys or []

    @property
    def next_key_hashes(self) -> list[str] | None:
        """Fetch a list of the `nextKeyHashes` entries from the parameters."""
        next_keys = self.params.get("nextKeyHashes")
        # Empty list is semantically equivalent to missing/null (no pre-rotation commitment)
        if next_keys is not None and not isinstance(next_keys, list):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid 'nextKeyHashes' parameter: expected list of strings"
                )
            )
        if next_keys is not None and not all(isinstance(k, str) for k in next_keys):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid 'nextKeyHashes' parameter: expected list of strings"
                )
            )
        # Return None for empty list to treat it as equivalent to missing
        return next_keys if next_keys else None

    @property
    def watchers(self) -> list | None:
        """Fetch the active `watchers` parameter value."""
        watchers = self.params.get("watchers")
        if watchers is not None and (
            not isinstance(watchers, list)
            or not all(isinstance(k, str) for k in watchers)
        ):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid 'watchers' parameter: expected list of strings"
                )
            )
        return watchers

    @property
    def witness(self) -> dict | None:
        """Fetch the active `witness` parameter value."""
        witness = self.params.get("witness")
        if witness is not None and not isinstance(witness, dict):
            raise InvalidDocumentState(
                ProblemDetails.invalid_parameter(
                    "Invalid 'witness' parameter: expected object"
                )
            )
        return witness

    @property
    def witness_rule(self) -> WitnessRule | None:
        """Fetch the active `witness` rules as a `WitnessRule` instance."""
        rule = self.witness
        if rule is not None:
            try:
                rule = WitnessRule.deserialize(rule)
            except ValueError as err:
                raise InvalidDocumentState(
                    ProblemDetails.invalid_parameter(str(err))
                ) from None
        return rule

    def create_proof(
        self,
        sk: SigningKey,
        *,
        timestamp: datetime | None = None,
        kid: str | None = None,
    ) -> dict:
        """Generate a proof for a document state with a signing key."""
        return di_jcs_sign(
            self.history_line(),
            sk,
            purpose="assertionMethod",
            timestamp=timestamp,
            kid=kid,
        )

    def sign(
        self,
        sk: SigningKey,
        *,
        timestamp: datetime | None = None,
        kid: str | None = None,
    ):
        """Create and append a new proof for a document state with a signing key."""
        self.proofs.append(self.create_proof(sk, timestamp=timestamp, kid=kid))

    def verify_proof(self, proof: dict, method: VerifyingKey | dict):
        """Verify a proof against a document state."""
        return di_jcs_verify(self.history_line(), proof, method)

    @classmethod
    def _update_params(cls, old_params: dict, new_params: dict) -> dict:
        res = old_params.copy()
        for param, pvalue in new_params.items():
            res[param] = pvalue
            if param == "deactivated":
                if pvalue not in (True, False):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'deactivated' parameter", found=pvalue
                        )
                    )
            elif param == "method":
                if not isinstance(pvalue, str) or not pvalue:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'method' parameter", found=pvalue
                        )
                    )
            elif param == "nextKeyHashes":
                # Empty list is semantically equivalent to missing/null
                if pvalue == []:
                    continue
                if not isinstance(pvalue, list) or not all(isinstance(k, str) for k in pvalue):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'nextKeyHashes' parameter",
                            found=pvalue,
                        )
                    )
            elif param == "portable":
                if not isinstance(pvalue, bool):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'portable' parameter", found=pvalue
                        )
                    )
                if pvalue and old_params and not old_params.get("portable"):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Parameter 'portable' may only be enabled in the first entry"
                        )
                    )
            elif param == "scid":
                if old_params:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Parameter 'scid' cannot be updated"
                        )
                    )
                if not isinstance(pvalue, str) or not pvalue:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'scid' parameter: expected string",
                            found=pvalue,
                        )
                    )
            elif param == "ttl":
                if not isinstance(pvalue, int) or pvalue <= 0:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'ttl' parameter",
                            found=pvalue,
                        )
                    )
            elif param == "updateKeys":
                if not isinstance(pvalue, list) or not all(isinstance(k, str) for k in pvalue):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'updateKeys' parameter",
                            found=pvalue,
                        )
                    )
            elif param == "watchers":
                if not isinstance(pvalue, list) or not all(isinstance(k, str) for k in pvalue):
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            "Unsupported value for 'watchers' parameter",
                            found=pvalue,
                        )
                    )
            elif param == "witness":
                try:
                    WitnessRule.deserialize(pvalue)
                except ValueError as err:
                    raise InvalidDocumentState(
                        ProblemDetails.invalid_parameter(
                            str(err),
                            found=pvalue,
                        )
                    ) from None
            else:
                raise InvalidDocumentState(
                    ProblemDetails.invalid_parameter(
                        f"Unsupported parameter: {param!r}",
                    )
                )
        return res


def check_version_time(
    state: DocumentState,
    prev_state: DocumentState | None,
    *,
    enforce_future_skew: bool = False,
    now: datetime | None = None,
) -> None:
    """Verify versionTime is present and monotonic across log entries.

    Monotonic ordering is always enforced. When ``enforce_future_skew`` is
    True, also reject ``versionTime`` more than five minutes after ``now``
    (did:webvh v1.0 SHOULD for resolver clock-skew tolerance).
    """
    if not state.timestamp_raw:
        raise InvalidDocumentState(
            ProblemDetails.invalid_log_entry(
                f"version '{state.version_number}' is missing versionTime",
                versionId=state.version_id,
            )
        )

    if enforce_future_skew:
        now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if state.timestamp > now + MAX_FUTURE_SKEW:
            raise InvalidDocumentState(
                ProblemDetails.invalid_log_entry(
                    f"versionTime for version '{state.version_number}' must not be "
                    f"more than 5 minutes in the future",
                    versionId=state.version_id,
                )
            )

    if prev_state and state.timestamp <= prev_state.timestamp:
        raise InvalidDocumentState(
            ProblemDetails.invalid_log_entry(
                f"versionTime for version '{state.version_number}' must be greater than previous entry time",
                versionId=state.version_id,
            )
        )


def verify_state_proofs(state: DocumentState, prev_state: DocumentState | None):
    """Verify all proofs on a document state."""
    proofs = state.proofs
    if not proofs:
        raise InvalidDocumentState(
            ProblemDetails(
                type="#proof-verification-failed",
                title="No proofs on log entry",
                versionId=state.version_id,
            )
        )
    if not prev_state or prev_state.next_key_hashes:
        update_keys = state.update_keys
    else:
        update_keys = prev_state.update_keys
    for proof in proofs:
        method_id = proof.get("verificationMethod")
        vmethod = resolve_did_key(method_id)
        if vmethod["publicKeyMultibase"] not in update_keys:
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#proof-verification-failed",
                    title="Proof verification failed",
                    detail=f"Update key not found: {method_id}",
                    versionId=state.version_id,
                )
            )
        try:
            state.verify_proof(
                proof=proof,
                method=vmethod,
            )
        except ValueError as err:
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#proof-verification-failed",
                    title="Proof verification failed",
                    detail=str(err),
                    versionId=state.version_id,
                )
            ) from None


def _canonicalize_log_line(line: dict) -> bytes:
    return jcs.canonicalize(line)
