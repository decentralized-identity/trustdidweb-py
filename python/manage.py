import asyncio
import base64
import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Generator, Optional, Sequence, Tuple, Union

import aries_askar
import jsoncanon
import jsonpatch

from multiformats import multibase, multicodec, multihash

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
METHOD = "webnext"
PLACEHOLDER = "{{SCID}}"
HISTORY_FILENAME = "did.log"
STORE_FILENAME = "keys.sqlite"
HISTORY_PROTO = "history:1"
BASE_PROTO = f"did:{METHOD}:1"


@dataclass
class KeyAlgorithm:
    name: str


@dataclass
class VerificationMethod:
    key: aries_askar.Key
    kid: str
    pk_codec: str

    def from_key(key: aries_askar.Key, kid: str = None) -> "VerificationMethod":
        if not kid:
            kid = "#" + key.get_jwk_thumbprint()
        if key.algorithm == aries_askar.KeyAlg.ED25519:
            pk_codec = "ed25519-pub"
        else:
            raise ValueError("Unsupported key algorithm")
        return VerificationMethod(key=key, kid=kid, pk_codec=pk_codec)


@dataclass
class ResolutionResult:
    document: Optional[dict] = None
    document_metadata: Optional[dict] = None
    resolution_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "didDocument": self.document,
            "didDocumentMetadata": self.document_metadata,
            "didResolutionMetadata": self.resolution_metadata,
        }


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


class ResolutionError(Exception):
    error: str
    message: Optional[str] = None

    def __init__(
        self,
        error: str,
        message: str = None,
        status_code: int = 400,
    ):
        super().__init__()
        self.error = error
        self.message = message
        self.status_code = status_code

    def serialize(self) -> dict:
        return {
            "error": self.error,
            "errorMessage": self.message,
            "contentType": "application/did+ld+json",
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
        scid_ver: int = 1,
    ):
        doc_id, doc_v1 = update_scid(document, scid_ver=scid_ver)

        # debug: checking the SCID derivation
        check_id, check_doc = update_scid(doc_v1, scid_ver=scid_ver)
        assert check_id == doc_id and check_doc == doc_v1

        if timestamp:
            timestamp, timestamp_raw = cls.load_timestamp(timestamp)
        else:
            timestamp, timestamp_raw = cls.new_timestamp()
        ret = DocumentState(
            params=params,
            params_update=params.copy(),
            document=doc_v1,
            document_update={"value": deepcopy(doc_v1)},
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            version_id=1,
            version_hash="",
            last_version_hash="",
            proofs=[],
        )
        ret.version_hash = ret.calculate_hash()
        return ret

    def calculate_hash(self) -> str:
        digest = sha256(
            jsoncanon.canonicalize(
                [
                    self.last_version_hash,
                    self.version_id,
                    self.timestamp_raw,
                    self.params_update,
                    self.document_update,
                ]
            )
        ).digest()
        return format_hash(digest)

    @classmethod
    def new_timestamp(cls) -> Tuple[datetime, str]:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
        return timestamp, format_datetime(timestamp)

    @classmethod
    def load_timestamp(cls, timestamp: Union[str, dict]) -> Tuple[datetime, str]:
        if isinstance(timestamp, str):
            timestamp_raw = timestamp
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(timestamp)
        else:
            timestamp_raw = format_datetime(timestamp)
        return timestamp, timestamp_raw

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
        if timestamp:
            timestamp, timestamp_raw = self.load_timestamp(timestamp)
        else:
            timestamp, timestamp_raw = self.new_timestamp()
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
                if pvalue != BASE_PROTO:
                    raise ValueError("Unsupported method parameter")
            else:
                raise ValueError(f"Unsupported history parameter: {param}")
            params[param] = pvalue
        if "method" not in params:
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
        if not prev_state:
            check_scid, _ = update_scid(document, scid_ver=1)
            if check_scid != document["id"]:
                raise ValueError("Invalid SCID derivation")

        timestamp, timestamp_raw = cls.load_timestamp(timestamp_raw)

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
            last_version_hash=prev_state.version_hash if prev_state else "",
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


async def auto_generate_did(
    domain: str, key_alg: KeyAlgorithm, pass_key: str, scid_ver=1
) -> Tuple[Path, DocumentState, VerificationMethod]:
    vm = VerificationMethod.from_key(aries_askar.Key.generate(key_alg.name))
    print(f"Generated inception key ({key_alg.name}): {vm.kid}")
    genesis = genesis_document(domain, [vm])
    doc_path, state = await provision_did(genesis, vm, pass_key, scid_ver=scid_ver)
    return (doc_path, state, vm)


async def provision_did(
    document: Union[str, dict], vm: VerificationMethod, pass_key: str, scid_ver=1
) -> Tuple[Path, DocumentState]:
    state = DocumentState.initial(
        params={"method": BASE_PROTO}, document=document, scid_ver=scid_ver
    )
    doc_id = state.document_id
    print(f"Initialized document: {doc_id}")

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    vm.kid = doc_id + vm.kid
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(vm.kid, vm.key)
    await store.close()

    state.proofs.append(eddsa_sign(state.document, vm, state.version_hash))
    write_document_state(doc_dir, state)

    return doc_dir, state


def write_document_state(
    doc_dir: Path,
    state: DocumentState,
):
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    if state.version_id > 1:
        mode = "a"
        if not history_path.exists():
            raise RuntimeError(f"History path does not exist: {history_path}")
    else:
        mode = "w"

    with open(history_path, mode) as out:
        print(
            json.dumps(state.history_line()),
            file=out,
        )

    # for debugging
    pretty = json.dumps(state.document, indent=2)
    with open(doc_dir.joinpath(f"did-v{state.version_id}.json"), "w") as out:
        print(pretty, file=out)

    print(f"Wrote document v{state.version_id} to {doc_dir}")


def load_history_path(
    path: Union[str, Path],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_hash: bool = True,
    verify_signature: bool = False,
) -> Tuple[DocumentState, DocumentMetadata]:
    with open(path, "r") as history:
        return load_history(
            history,
            version_id=version_id,
            version_time=version_time,
            verify_hash=verify_hash,
            verify_signature=verify_signature,
        )


def load_history(
    history: Sequence[str],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_hash: bool = True,
    verify_signature: bool = False,
) -> Tuple[DocumentState, DocumentMetadata]:
    created = None
    prev = None
    # iterator is guaranteed to return at least one state, or raise ValueError
    states = iter_history(
        history, verify_hash=verify_hash, verify_signature=verify_signature
    )
    for latest in states:
        if not created:
            created = latest.timestamp
        if version_id and version_id == latest.version_id:
            break
        if version_time and version_time < latest.timestamp:
            if not prev:
                raise ValueError(f"Cannot resolve versionTime: {version_time}")
            latest = prev
            break
        prev = latest
    if version_id and version_id != latest.version_id:
        raise ValueError(f"Cannot resolve versionId: {version_id}")
    return latest, DocumentMetadata(
        created=created,
        updated=latest.timestamp,
        deactivated=latest.deactivated,
        version_id=latest.version_id,
    )


def iter_history(
    history: Sequence[str], verify_hash: bool, verify_signature: bool
) -> Generator[DocumentState, None, None]:
    prev_state: DocumentState = None

    for line in history:
        if not line:
            continue
        parts = json.loads(line)
        state = DocumentState.load_history_line(parts, prev_state)
        if verify_hash:
            if state.calculate_hash() != state.version_hash:
                raise ValueError("Invalid history version hash")

        if verify_signature:
            doc_id = state.document_id
            proofs = state.proofs
            if not proofs:
                raise ValueError("Missing history version proof(s)")
            controllers = (prev_state or state).controllers()
            auth_keys = (prev_state or state).authentication_keys()
            for proof in proofs:
                method_id = proof.get("verificationMethod")
                if not isinstance(method_id, str):
                    raise ValueError("Invalid proof verification method")
                if "#" not in method_id:
                    raise ValueError(
                        "Expected verification method reference with fragment"
                    )
                if method_id.startswith("#"):
                    method_id = doc_id + method_id
                    method_ctl = doc_id
                else:
                    fpos = method_id.find("#")
                    method_ctl = method_id[:fpos]
                if method_id not in auth_keys:
                    raise ValueError(f"Cannot resolve verification method: {method_id}")
                if method_ctl not in controllers:
                    raise ValueError(f"Controller is not authorized: {method_ctl}")
                vmethod = auth_keys[method_id]
                verify_proof(state.document, proof, vmethod)

        yield state
        prev_state = state

    if not prev_state:
        raise ValueError("Empty document history")


def format_hash(digest: bytes) -> str:
    return multibase.encode(multihash.wrap(digest, "sha2-256"), "base58btc")


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


def verify_proof(document: dict, proof: dict, method: dict):
    if proof.get("type") != "DataIntegrityProof":
        raise ValueError("Unsupported proof type")
    if proof.get("proofPurpose") != "authentication":
        raise ValueError("Expected proof purpose: 'authentication'")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise ValueError("Unsupported cryptosuite for proof")
    key_mc = multibase.decode(method.get("publicKeyMultibase"))
    (codec, key_bytes) = multicodec.unwrap(key_mc)
    if codec.name != "ed25519-pub":
        raise ValueError(f"Unsupported key type: {codec.name}")
    key = aries_askar.Key.from_public_bytes("ed25519", key_bytes)
    document = document.copy()
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    if not key.verify_signature(sig_input, signature):
        raise ValueError("Invalid signature for proof")


def update_document_state(
    prev_state: DocumentState,
    document: dict,
    vm: VerificationMethod,
    params_update: dict = None,
    timestamp: Union[str, datetime] = None,
) -> DocumentState:
    state = prev_state.create_next(
        document, params_update=params_update, timestamp=timestamp
    )
    state.proofs.append(eddsa_sign(state.document, vm, state.version_hash))
    return state


def genesis_document(domain: str, keys: list[VerificationMethod]) -> str:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    doc = {
        "@context": [DID_CONTEXT, MKEY_CONTEXT],
        "id": f"did:webnext:{domain}:{PLACEHOLDER}",
        "authentication": [],
        "verificationMethod": [],
    }
    for vm in keys:
        add_auth_key(doc, vm)
    return json.dumps(doc, indent=2)


def add_auth_key(document: dict, vm: VerificationMethod):
    mkey = multibase.encode(
        multicodec.wrap(vm.pk_codec, vm.key.get_public_bytes()), "base58btc"
    )
    kid = vm.kid
    fpos = kid.find("#")
    if fpos < 0:
        raise RuntimeError("Missing fragment in verification method ID")
    elif fpos > 0:
        controller = kid[:fpos]
    else:
        controller = document["id"]
        kid = controller + kid
    document["authentication"].append(kid)
    document["verificationMethod"].append(
        {
            "id": kid,
            "type": "Multikey",
            "controller": controller,
            "publicKeyMultibase": mkey,
        }
    )


def update_scid(document: Union[dict, str], scid_ver) -> Tuple[str, dict]:
    if isinstance(document, str):
        document = json.loads(document)
    else:
        document = document.copy()
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise ValueError("Missing document ID")
    id_parts = doc_id.split(":")
    if (
        len(id_parts) < 4
        or id_parts[0] != "did"
        or id_parts[1] != METHOD
        or "" in id_parts
    ):
        raise ValueError("Invalid document ID")
    id_parts.pop()
    if scid_ver != 1:
        raise ValueError("Only SCID version 1 is supported")
    id_parts.append(PLACEHOLDER)
    plc_id = ":".join(id_parts)
    norm = (
        jsoncanon.canonicalize(document)
        .decode("ascii")
        .replace(doc_id, plc_id)
        .encode("ascii")
    )
    scid = base64.b32encode(sha256(norm).digest()).decode("ascii").lower()[:24]
    id_parts.pop()
    id_parts.append(scid)
    upd_id = ":".join(id_parts)
    return upd_id, json.loads(json.dumps(document).replace(doc_id, upd_id))


def eddsa_sign(document: dict, sk: VerificationMethod, challenge: str) -> dict:
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": sk.kid,
        "created": format_datetime(datetime.now(timezone.utc)),
        "challenge": challenge,
        "proofPurpose": "authentication",
    }
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    proof["proofValue"] = multibase.encode(sk.key.sign_message(sig_input), "base58btc")
    return proof


def format_datetime(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def resolve_did(
    did: str,
    history: Sequence[str],
    *,
    version_id: int = None,
    version_time: datetime = None,
) -> ResolutionResult:
    try:
        state, meta = load_history(
            history,
            verify_signature=True,
            version_id=version_id,
            version_time=version_time,
        )
    except ValueError as err:
        return ResolutionResult(
            resolution_metadata=ResolutionError("invalidDid", str(err)).serialize()
        )
    if state.document_id != did:
        return ResolutionResult(
            resolution_metadata=ResolutionError(
                "invalidDid", "Document @id mismatch"
            ).serialize()
        )
    return ResolutionResult(document=state.document, document_metadata=meta.serialize())


async def demo():
    pass_key = "password"
    (doc_dir, state, vm) = await auto_generate_did(
        "domain.example", KeyAlgorithm(name="ed25519"), pass_key=pass_key, scid_ver=1
    )
    created = state.timestamp

    # gen v2 - add external controller
    ctl_id = "did:example:controller"
    doc = state.document_copy()
    doc["controller"] = [doc["id"], ctl_id]
    store_path = doc_dir.joinpath(STORE_FILENAME)
    ctl_sk = aries_askar.Key.generate("ed25519")
    ctl_vm = VerificationMethod.from_key(
        ctl_sk, ctl_id + "#" + ctl_sk.get_jwk_thumbprint()
    )
    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)
    async with store.session() as session:
        await session.insert_key(ctl_vm.kid, ctl_vm.key)
    await store.close()
    add_auth_key(doc, ctl_vm)
    state = update_document_state(state, doc, vm)  # sign with genesis key
    write_document_state(doc_dir, state)

    # gen v3 - add services
    doc = state.document_copy()
    doc["@context"].extend(
        [
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ]
    )
    doc["service"] = [
        {
            "id": doc["id"] + "#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://domain.example",
        },
        {
            "id": doc["id"] + "#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://domain.example/.well-known/whois.jsonld",
        },
    ]
    state = update_document_state(state, doc, ctl_vm)  # sign with controller key
    write_document_state(doc_dir, state)

    # verify history
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    check_state, meta = load_history_path(history_path, verify_signature=True)
    assert check_state == state
    assert meta.created == created
    assert meta.updated == state.timestamp
    assert meta.deactivated == False
    assert meta.version_id == 3

    # test resolver
    with open(history_path) as history:
        resolution = resolve_did(doc["id"], history)
    assert resolution.document == state.document
    assert resolution.document_metadata["created"] == format_datetime(created)
    assert resolution.document_metadata["updated"] == state.timestamp_raw
    assert resolution.document_metadata["deactivated"] == False
    assert resolution.document_metadata["versionId"] == "3"
    with open(history_path) as history:
        resolution = resolve_did(doc["id"], history, version_id=2)
    assert resolution.document_metadata["versionId"] == "2"


asyncio.run(demo())
