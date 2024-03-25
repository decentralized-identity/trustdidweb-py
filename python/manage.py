import asyncio
import base64
import json

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


async def auto_generate_did(
    domain: str, key_alg: KeyAlgorithm, pass_key: str, scid_ver=1
) -> Tuple[Path, VerificationMethod]:
    vm = VerificationMethod.from_key(aries_askar.Key.generate(key_alg.name))
    print(f"Generated inception key ({key_alg.name}): {vm.kid}")
    genesis = genesis_document(domain, [vm])
    doc_path = await provision_did(genesis, vm, pass_key, scid_ver=scid_ver)
    return (doc_path, vm)


async def provision_did(
    document: Union[str, dict], vm: VerificationMethod, pass_key: str, scid_ver=1
) -> Path:
    doc_id, doc_v1 = update_scid(document, scid_ver=scid_ver)
    print(f"Initialized document: {doc_id}")

    # debug: checking the SCID derivation
    check_id, check_doc = update_scid(doc_v1, scid_ver=scid_ver)
    assert check_id == doc_id and check_doc == doc_v1

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)
    init_hash = init_log(doc_dir, doc_id)

    vm.kid = doc_id + vm.kid
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(vm.kid, vm.key)
    await store.close()

    write_document(doc_dir, doc_v1, None, init_hash, 1, new_timestamp(), vm)

    return doc_dir


def write_document(
    doc_dir: Path,
    document: dict,
    prev_document: Optional[dict],
    prev_hash: str,
    version_id: int,
    timestamp: str,
    vm: VerificationMethod,
):
    patch = jsonpatch.make_patch(prev_document, document).patch
    cur_hash = log_line_hash(prev_hash, version_id, timestamp, patch)
    proof = eddsa_sign(document, vm, cur_hash)
    with open(doc_dir.joinpath(LOG_FILENAME), "a+") as out:
        print(json.dumps([cur_hash, version_id, timestamp, patch, [proof]]), file=out)

    pretty = json.dumps(document, indent=2)
    with open(doc_dir.joinpath(f"did-v{version_id}.json"), "w") as out:
        print(pretty, file=out)
    with open(doc_dir.joinpath(f"did.json"), "w") as out:
        print(pretty, file=out)

    print(f"Wrote document v{version_id} to {doc_dir}")


def load_log(
    path: Union[str, Path], verify_hash: bool, verify_signature: bool
) -> Generator[Tuple[int, str, list], None, None]:
    """This currently loads every document version into memory."""
    index = 1
    doc = None
    prev_hash = None
    prev_controllers = []
    prev_auth_keys = {}
    doc_id = None

    with open(path) as history:
        lines = iter(history)
        header = json.loads(next(lines))
        if not isinstance(header, list) or len(header) != 5:
            raise RuntimeError("Invalid log: header not parsable")
        if header[1] != HISTORY_PROTO:
            raise RuntimeError("Invalid log: unsupported version")
        base_proto, log_id = header[2:4]
        if base_proto != BASE_PROTO:
            raise RuntimeError("Invalid log: unsupported protocol")
        prev_hash = log_header_hash(base_proto, log_id)
        if prev_hash != header[0]:
            raise RuntimeError("Invalid log: incorrect header hash")
        doc_id = f"did:{METHOD}:{log_id}"

        for line in lines:
            if not line:
                continue
            parts = json.loads(line)
            if not isinstance(parts, list) or len(parts) != 5:
                raise RuntimeError("Invalid log: not parsable")
            (log_hash, version_id, timestamp, patch, proofs) = parts
            doc = jsonpatch.apply_patch(doc, patch)
            if not isinstance(doc, dict):
                raise RuntimeError("Invalid log: invalid document")
            if verify_hash:
                check_hash = log_line_hash(prev_hash, version_id, timestamp, patch)
                if check_hash != log_hash:
                    raise RuntimeError("Invalid log: incorrect data hash")

            check_id = doc.get("id")
            if check_id != doc_id:
                raise RuntimeError("Invalid log: document ID has changed")
            if index == 1:
                check_scid, _ = update_scid(doc, scid_ver=1)
                if check_scid != doc_id:
                    raise RuntimeError("Invalid log: invalid SCID derivation")

            controllers = doc.get("controller")
            if controllers is None:
                controllers = [doc_id]
            elif isinstance(controllers, str):
                controllers = [controllers]
            elif not isinstance(controllers, list):
                raise RuntimeError("Invalid log: invalid controllers")

            auth_keys = {}
            if verify_signature:
                vmethods = doc.get("verificationMethod", [])
                vm_dict = {}
                if not isinstance(vmethods, list):
                    raise RuntimeError("Invalid log: invalid verification methods")
                for method in vmethods:
                    _ = parse_verification_method(method, doc_id, vm_dict)
                auths = doc.get("authentication", [])
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

                if index == 1:
                    prev_controllers = controllers
                    prev_auth_keys = auth_keys

                if doc_id not in prev_controllers:
                    raise RuntimeError("Invalid log: DID missing from controllers")
                proofs = doc.get("proof", [])
                if isinstance(proofs, dict):
                    proofs = [proofs]
                if not isinstance(proofs, list):
                    raise RuntimeError("Invalid log: invalid or missing proof")
                for proof in proofs:
                    if not isinstance(proof, dict):
                        raise RuntimeError("Invalid log: invalid proof")
                    method_id = proof.get("verificationMethod")
                    if not isinstance(method_id, str):
                        raise RuntimeError(
                            "Invalid log: invalid proof verification method"
                        )
                    if "#" not in method_id:
                        raise RuntimeError(
                            "Invalid log: expected verification method reference with fragment"
                        )
                    if method_id.startswith("#"):
                        method_id = doc_id + method_id
                        method_ctl = doc_id
                    else:
                        fpos = method_id.find("#")
                        method_ctl = method_id[:fpos]
                    if method_id not in prev_auth_keys:
                        raise RuntimeError(
                            "Invalid log: cannot resolve verification method"
                        )
                    if method_ctl not in prev_controllers:
                        raise RuntimeError(
                            f"Invalid log: not a listed controller ({method_ctl})"
                        )
                    vmethod = prev_auth_keys[method_id]
                    verify_proof(doc, proof, vmethod)

            yield (index, log_hash, doc.copy())

            prev_hash = log_hash
            prev_controllers = controllers
            prev_auth_keys = auth_keys
            index += 1

    if not index:
        raise RuntimeError("Invalid log: no entries")


def new_timestamp() -> str:
    return format_datetime(datetime.now(timezone.utc))


def format_hash(digest: bytes) -> str:
    return multibase.encode(multihash.wrap(digest, "sha2-256"), "base58btc")


def init_log(doc_dir: Path, doc_id: str) -> str:
    ident = doc_id.removeprefix(f"did:{METHOD}:")
    header_hash = log_header_hash(BASE_PROTO, ident)
    header = [header_hash, HISTORY_PROTO, BASE_PROTO, ident, {}]
    with open(doc_dir.joinpath(LOG_FILENAME), "w") as log:
        print(json.dumps(header), file=log)
    return header[0]


def log_header_hash(base_proto: str, doc_id: str):
    digest = sha256(jsoncanon.canonicalize([base_proto, doc_id])).digest()
    return format_hash(digest)


def log_line_hash(prev_hash: str, version_id: int, timestamp: str, patch: dict):
    digest = sha256(
        jsoncanon.canonicalize([prev_hash, version_id, timestamp, patch])
    ).digest()
    return format_hash(digest)


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
    del document["proof"]
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    proof = proof.copy()
    signature = multibase.decode(proof.pop("proofValue"))
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    if not key.verify_signature(sig_input, signature):
        raise RuntimeError("Invalid proof signature")


def update_document(dir_path: str, vm: Optional[VerificationMethod] = None) -> dict:
    doc_dir = Path(dir_path)
    if not doc_dir.is_dir():
        raise RuntimeError(f"Missing document directory: {dir_path}")
    doc_path = doc_dir.joinpath("did.json")
    log_path = doc_dir.joinpath(LOG_FILENAME)
    if not doc_path.is_file():
        raise RuntimeError(f"Missing document file: {doc_path}")
    if not log_path.is_file():
        raise RuntimeError(f"Missing log file: {log_path}")
    # FIXME in future only verifier needs to check signatures?
    *_, (prev_ver, prev_hash, prev_doc) = load_log(
        log_path, verify_hash=True, verify_signature=True
    )

    with open(doc_path) as infile:
        document = json.load(infile)
    if not isinstance(document, dict):
        raise RuntimeError("Invalid document format")
    version_id = prev_ver + 1

    write_document(
        doc_dir, document, prev_doc, prev_hash, version_id, new_timestamp(), vm
    )
    return document


def find_signing_key(document: dict) -> str:
    # FIXME: check authentication block and resolve references
    for ver_method in document["verificationMethod"]:
        kid = ver_method.get("id")
        if not isinstance(kid, str):
            raise RuntimeError("Invalid verification method")
        if kid.startswith("#"):
            kid = f"{document['id']}{kid}"
        return kid
    raise RuntimeError("Error determining signing key")


async def load_key(store_path: Path, pass_key: str, kid: str) -> VerificationMethod:
    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)
    try:
        async with store.session() as session:
            key_entry = await session.fetch_key(kid)
            if not key_entry:
                raise RuntimeError(f"Key not found: {kid}")
            return VerificationMethod.from_key(key_entry.key, kid=kid)
    finally:
        await store.close()


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
    fpos = vm.kid.find("#")
    if fpos > 0:
        controller = vm.kid[:fpos]
    else:
        controller = document["id"]
    kid = vm.kid
    if kid.startswith("#"):
        kid = document["id"] + kid
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
        "verificationMethod": document["id"] + "#" + sk.kid,
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
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


async def demo():
    pass_key = "password"
    (doc_dir, vm) = await auto_generate_did(
        "example.com", KeyAlgorithm(name="ed25519"), pass_key=pass_key, scid_ver=1
    )

    # gen v2 - add external controller
    with open(doc_dir.joinpath("did.json")) as infile:
        doc = json.load(infile)
    ctl_id = "did:example:controller"
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
    with open(doc_dir.joinpath("did.json"), "w") as outfile:
        json.dump(doc, outfile)
    doc = update_document(doc_dir, ctl_vm)

    # gen v3 - add alsoKnownAs
    with open(doc_dir.joinpath("did.json")) as infile:
        doc = json.load(infile)
    doc["alsoKnownAs"] = ["did:web:example.com"]
    with open(doc_dir.joinpath("did.json"), "w") as outfile:
        json.dump(doc, outfile)
    doc = update_document(doc_dir, vm)


asyncio.run(demo())
