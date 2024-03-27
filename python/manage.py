import asyncio
import base64
import json

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Generator, Optional, Tuple, Union

import aries_askar
import jsoncanon
import jsonpatch

from multiformats import multibase, multicodec, multihash

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
DI_CONTEXT = "https://w3id.org/security/data-integrity/v2"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
METHOD = "webnext"
PLACEHOLDER = "{{SCID}}"
LOG_FILENAME = "did-history.log"
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
            raise RuntimeError("Unsupported key algorithm")
        return VerificationMethod(key=key, kid=kid, pk_codec=pk_codec)


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
        document: dict,
        timestamp: Optional[Union[str, datetime]] = None,
    ):
        if timestamp:
            timestamp, timestamp_raw = cls.load_timestamp(timestamp)
        else:
            timestamp, timestamp_raw = cls.new_timestamp()
        ret = DocumentState(
            params=params,
            params_update=params.copy(),
            document=deepcopy(document),
            document_update={"value": deepcopy(document)},
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
            raise RuntimeError("invalid log line")
        (version_hash, version_id, timestamp_raw, params_update, doc_update, proofs) = (
            parts
        )
        if not isinstance(params_update, dict):
            raise RuntimeError("invalid params")
        if not isinstance(doc_update, dict) or not ("value" in doc_update) ^ (
            "patch" in doc_update
        ):
            raise RuntimeError("invalid data")

        params = prev_state.params.copy() if prev_state else {}
        for param, pvalue in params_update.items():
            if param == "method":
                if pvalue != BASE_PROTO:
                    raise RuntimeError("unsupported method")
            else:
                raise RuntimeError(f"unsupported parameter ({param})")
            params[param] = pvalue
        if "method" not in params:
            raise RuntimeError("invalid initial parameters")

        check_ver = prev_state.version_id + 1 if prev_state else 1
        if check_ver != version_id:
            raise RuntimeError("version ID mismatch")

        if "value" in doc_update:
            document = doc_update["value"]
        else:
            if not prev_state:
                raise RuntimeError("invalid initial data")
            # FIXME wrap error
            document = jsonpatch.apply_patch(prev_state.document, doc_update["patch"])

        if not isinstance(document, dict) or "id" not in document:
            raise RuntimeError("invalid document state")

        # check SCID derivation for first version
        if not prev_state:
            check_scid, _ = update_scid(document, scid_ver=1)
            if check_scid != document["id"]:
                raise RuntimeError("invalid SCID derivation")

        timestamp, timestamp_raw = cls.load_timestamp(timestamp_raw)

        if not isinstance(proofs, list) or any(
            not isinstance(prf, dict) for prf in proofs
        ):
            raise RuntimeError("invalid proofs")

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

    def document_copy(self) -> dict:
        return deepcopy(self.document)

    def controllers(self) -> list[str]:
        ctls = self.document.get("controller")
        if ctls is None:
            ctls = [self.document_id]
        elif isinstance(ctls, str):
            ctls = [ctls]
        elif not isinstance(ctls, list):
            raise RuntimeError("Invalid log: invalid controllers")
        return ctls

    def authentication_keys(self) -> dict[str, dict]:
        doc_id = self.document_id
        auth_keys = {}
        vmethods = self.document.get("verificationMethod", [])
        vm_dict = {}
        if not isinstance(vmethods, list):
            raise RuntimeError("invalid verification methods")
        for method in vmethods:
            _ = parse_verification_method(method, doc_id, vm_dict)
        auths = self.document.get("authentication", [])
        if not isinstance(auths, list):
            raise RuntimeError("Invalid log: invalid authentication")
        for auth in auths:
            if isinstance(auth, str):
                if auth.startswith("#"):
                    auth = doc_id + auth
                if auth not in vm_dict:
                    raise RuntimeError(
                        f"Invalid log: invalid authentication key reference ({auth})"
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
    doc_id, doc_v1 = update_scid(document, scid_ver=scid_ver)
    print(f"Initialized document: {doc_id}")

    # debug: checking the SCID derivation
    check_id, check_doc = update_scid(doc_v1, scid_ver=scid_ver)
    assert check_id == doc_id and check_doc == doc_v1

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    vm.kid = doc_id + vm.kid
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(vm.kid, vm.key)
    await store.close()

    state = DocumentState.initial(
        params={"method": BASE_PROTO},
        document=doc_v1,
    )
    state.proofs.append(eddsa_sign(state.document, vm, state.version_hash))
    write_document_state(doc_dir, state)

    return doc_dir, state


def write_document_state(
    doc_dir: Path,
    state: DocumentState,
):
    log_path = doc_dir.joinpath(LOG_FILENAME)
    if state.version_id > 1:
        mode = "a"
        if not log_path.exists():
            raise RuntimeError(f"log path does not exist: {log_path}")
    else:
        mode = "w"

    with open(log_path, mode) as out:
        print(
            json.dumps(state.history_line()),
            file=out,
        )

    # for debugging
    pretty = json.dumps(state.document, indent=2)
    with open(doc_dir.joinpath(f"did-v{state.version_id}.json"), "w") as out:
        print(pretty, file=out)

    print(f"Wrote document v{state.version_id} to {doc_dir}")


def load_log(
    log_path: Union[str, Path],
    *,
    verify_hash: bool = True,
    verify_signature: bool = False,
) -> DocumentState:
    *_, ret = iter_log(
        log_path, verify_hash=verify_hash, verify_signature=verify_signature
    )
    return ret


def iter_log(
    path: Union[str, Path], verify_hash: bool, verify_signature: bool
) -> Generator[DocumentState, None, None]:
    prev_state: DocumentState = None

    with open(path, "r") as history:
        for line in history:
            if not line:
                continue
            parts = json.loads(line)
            state = DocumentState.load_history_line(parts, prev_state)
            if verify_hash:
                if state.calculate_hash() != state.version_hash:
                    raise RuntimeError("invalid version hash")

            if verify_signature:
                doc_id = state.document_id
                proofs = state.proofs
                if not proofs:
                    raise RuntimeError("missing version proof(s)")
                controllers = (prev_state or state).controllers()
                auth_keys = (prev_state or state).authentication_keys()
                for proof in proofs:
                    method_id = proof.get("verificationMethod")
                    if not isinstance(method_id, str):
                        raise RuntimeError("invalid proof verification method")
                    if "#" not in method_id:
                        raise RuntimeError(
                            "expected verification method reference with fragment"
                        )
                    if method_id.startswith("#"):
                        method_id = doc_id + method_id
                        method_ctl = doc_id
                    else:
                        fpos = method_id.find("#")
                        method_ctl = method_id[:fpos]
                    if method_id not in auth_keys:
                        raise RuntimeError(
                            f"cannot resolve verification method: {method_id}"
                        )
                    if method_ctl not in controllers:
                        raise RuntimeError(f"not a listed controller: {method_ctl}")
                    vmethod = auth_keys[method_id]
                    verify_proof(state.document, proof, vmethod)

            yield state
            prev_state = state

    if not prev_state:
        raise RuntimeError("empty log")


def format_hash(digest: bytes) -> str:
    return multibase.encode(multihash.wrap(digest, "sha2-256"), "base58btc")


def parse_verification_method(method: dict, doc_id: str, method_dict: dict) -> str:
    if not isinstance(method, dict):
        raise RuntimeError("Invalid log: invalid verification methods")
    method_id = method.get("id")
    if not isinstance(method_id, str):
        raise RuntimeError("Invalid log: invalid verification method ID")
    if method_id.startswith("#"):
        method_id = doc_id + method_id
    if method_id in method_dict:
        raise RuntimeError("Invalid log: duplicate verification method ID")
    method_dict[method_id] = method
    return method_id


def verify_proof(document: dict, proof: dict, method: dict):
    if proof.get("type") != "DataIntegrityProof":
        raise RuntimeError("Unsupported proof type")
    if proof.get("proofPurpose") != "authentication":
        raise RuntimeError("Expected authentication proof purpose")
    if proof.get("cryptosuite") != "eddsa-jcs-2022":
        raise RuntimeError("Unsupported cryptosuite")
    key_mc = multibase.decode(method.get("publicKeyMultibase"))
    (codec, key_bytes) = multicodec.unwrap(key_mc)
    if codec.name != "ed25519-pub":
        raise RuntimeError("Unsupported key type")
    key = aries_askar.Key.from_public_bytes("ed25519", key_bytes)
    document = document.copy()
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    if not key.verify_signature(sig_input, signature):
        raise RuntimeError("Invalid proof signature")


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
        "@context": [DID_CONTEXT, DI_CONTEXT, MKEY_CONTEXT],
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
        raise RuntimeError("missing fragment in verification method ID")
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
        raise RuntimeError("Missing document ID")
    id_parts = doc_id.split(":")
    if (
        len(id_parts) < 4
        or id_parts[0] != "did"
        or id_parts[1] != METHOD
        or "" in id_parts
    ):
        raise RuntimeError("Invalid document ID")
    id_parts.pop()
    if scid_ver != 1:
        raise RuntimeError("Only SCID version 1 is supported")
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


async def demo():
    pass_key = "password"
    (doc_dir, state, vm) = await auto_generate_did(
        "domain.example", KeyAlgorithm(name="ed25519"), pass_key=pass_key, scid_ver=1
    )

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

    # verify log
    check_state = load_log(doc_dir.joinpath(LOG_FILENAME), verify_signature=True)
    assert check_state == state


asyncio.run(demo())
