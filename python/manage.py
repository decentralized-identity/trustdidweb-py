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

from multiformats import CID, multibase, multicodec

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
DI_CONTEXT = "https://w3id.org/security/data-integrity/v2"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
METHOD = "webnext"
PLACEHOLDER = "{{SCID}}"
LOG_FILENAME = "did.json.log"
STORE_FILENAME = "keys.sqlite"


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
            kid = key.get_jwk_thumbprint()
        if key.algorithm == aries_askar.KeyAlg.ED25519:
            pk_codec = "ed25519-pub"
        else:
            raise RuntimeError("Unsupported key algorithm")
        return VerificationMethod(key=key, kid=kid, pk_codec=pk_codec)


async def auto_generate_did(
    domain: str, key_alg: KeyAlgorithm, pass_key: str, scid_ver=1
) -> Path:
    sk = VerificationMethod.from_key(aries_askar.Key.generate(key_alg.name))
    print(f"Generated inception key ({key_alg.name}): {sk.kid}")
    genesis = genesis_document(domain, [sk])
    doc_id, doc_v1 = update_scid(genesis, scid_ver=scid_ver)
    print(f"Generated document: {doc_id}")
    assert doc_v1.get("previousHash") is None

    # debug: checking the SCID derivation
    check_id, _ = update_scid(doc_v1)
    assert check_id == doc_id

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(sk.kid, sk.key)
    await store.close()

    proof = eddsa_sign(doc_v1, sk)
    write_document(doc_v1, None, doc_dir, 1, proof=proof)

    return doc_dir


def write_document(
    document: dict,
    prev_document: Optional[dict],
    doc_dir: Path,
    version_id: int,
    cid: str = None,
    proof: Optional[dict] = None,
):
    updated = document["updated"]
    if not cid:
        cid = derive_version_cid(document).encode()
    if proof:
        document["proof"] = proof
    diff = jsonpatch.make_patch(prev_document, document).patch
    with open(doc_dir.joinpath(LOG_FILENAME), "a+") as out:
        print(json.dumps([cid, updated, diff]), file=out)

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
    prev_cid = None
    prev_controllers = []
    prev_auth_keys = {}
    doc_id = None

    for line in open(path):
        if not line:
            continue
        parts = json.loads(line)
        if not isinstance(parts, list) or len(parts) != 3:
            raise RuntimeError("Invalid log: not parsable")
        (cid, updated, diff) = parts
        doc = jsonpatch.apply_patch(doc, diff)
        if not isinstance(doc, dict):
            raise RuntimeError("Invalid log: invalid document")
        if verify_hash:
            check_cid = derive_version_cid(doc).encode()
            if check_cid != cid:
                raise RuntimeError("Invalid log: hash mismatch")
        if doc.get("previousHash") != prev_cid:
            raise RuntimeError("Invalid log: invalid previous hash")
        if doc.get("updated") != updated:
            raise RuntimeError("Invalid log: update time mismatch")

        check_id = doc.get("id")
        if not isinstance(check_id, str):
            raise RuntimeError("Invalid log: invalid document ID")
        if index == 1:
            derive_id, _ = update_scid(doc)
            if check_id != derive_id:
                raise RuntimeError("Invalid log: invalid SCID derivation")
            doc_id = check_id
        elif check_id != doc_id:
            raise RuntimeError("Invalid log: document ID has changed")

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
                    if not auth.startswith(doc_id + "#"):
                        raise RuntimeError(
                            "Invalid log: only local authentication keys supported"
                        )
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
                print(doc_id, prev_controllers)
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
                    raise RuntimeError("Invalid log: invalid proof verification method")
                if method_id.startswith("#"):
                    method_id = doc_id + method_id
                if method_id not in prev_auth_keys:
                    raise RuntimeError(
                        "Invalid log: cannot resolve verification method"
                    )
                vmethod = prev_auth_keys[method_id]
                verify_proof(doc, proof, vmethod)

        yield (index, cid, doc.copy())
        prev_cid = cid
        prev_controllers = controllers
        prev_auth_keys = auth_keys
        index += 1

    if not index:
        raise RuntimeError("Invalid log: no entries")


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


async def update_document(dir_path: str, pass_key: str) -> dict:
    doc_dir = Path(dir_path)
    if not doc_dir.is_dir():
        raise RuntimeError(f"Missing document directory: {dir_path}")
    doc_path = doc_dir.joinpath("did.json")
    log_path = doc_dir.joinpath(LOG_FILENAME)
    store_path = doc_dir.joinpath(STORE_FILENAME)
    if not doc_path.is_file():
        raise RuntimeError(f"Missing document file: {doc_path}")
    if not log_path.is_file():
        raise RuntimeError(f"Missing log file: {log_path}")
    # FIXME in future only verifier needs to check signatures?
    *_, (latest_ver, latest_hash, latest_doc) = load_log(
        log_path, verify_hash=True, verify_signature=True
    )

    with open(doc_path) as infile:
        document = json.load(infile)
    if not isinstance(document, dict):
        raise RuntimeError("Invalid document format")
    doc_id = document.get("id")
    version_id = latest_ver + 1
    document["previousHash"] = latest_hash
    # FIXME accept an updated date?
    document["updated"] = format_datetime(datetime.now(timezone.utc))
    if "proof" in document:
        del document["proof"]

    # look up the signing key
    # FIXME: check authentication block and resolve references
    kid = None
    for ver_method in document["verificationMethod"]:
        kid = ver_method.get("id")
        if not isinstance(kid, str):
            raise RuntimeError("Invalid verification method")
        kid = kid.removeprefix(doc_id).lstrip("#")
        break
    if not kid:
        raise RuntimeError("Error determining signing key")

    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)
    async with store.session() as session:
        key_entry = await session.fetch_key(kid)
        if not key_entry:
            raise RuntimeError(f"Key not found: {kid}")
        sk = VerificationMethod.from_key(key_entry.key, kid=kid)
    await store.close()

    proof = eddsa_sign(document, sk)
    write_document(document, latest_doc, doc_dir, version_id, proof=proof)
    return document


def genesis_document(domain: str, keys: list[VerificationMethod]) -> str:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    now = format_datetime(datetime.now(timezone.utc))
    doc = {
        "@context": [DID_CONTEXT, DI_CONTEXT, MKEY_CONTEXT],
        "id": f"did:webnext:{domain}:{PLACEHOLDER}",
        "created": now,
        "updated": now,
        "authentication": [],
        "verificationMethod": [],
    }
    for vm in keys:
        kid = doc["id"] + "#" + vm.kid
        mkey = multibase.encode(
            multicodec.wrap(vm.pk_codec, vm.key.get_public_bytes()), "base58btc"
        )
        doc["authentication"].append(kid)
        doc["verificationMethod"].append(
            {
                "id": kid,
                "type": "Multikey",
                "controller": doc["id"],
                "publicKeyMultibase": mkey,
            }
        )
    return json.dumps(doc, indent=2)


def derive_version_cid(document: Union[dict, str]) -> CID:
    if isinstance(document, str):
        document = json.loads(document)
    else:
        document = document.copy()
    if "proof" in document:
        del document["proof"]
    norm = jsoncanon.canonicalize(document)
    hash = sha256(norm).digest()
    return CID(base="base32", version=1, codec="json-jcs", digest=("sha2-256", hash))


def update_scid(document: Union[dict, str], scid_ver=None) -> Tuple[str, dict]:
    if isinstance(document, str):
        document = json.loads(document)
    else:
        document = document.copy()
    if "proof" in document:
        del document["proof"]
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise RuntimeError("Missing document ID")
    id_parts = doc_id.split(":")
    if id_parts[0] != "did" or len(id_parts) < 4:
        # FIXME check method identifier
        raise RuntimeError("Invalid document ID")
    old_scid: str = id_parts.pop()
    if scid_ver is None:
        pfx = old_scid[:1]
        if pfx.isdigit():
            scid_ver = int(pfx)
        else:
            scid_ver = 1  # use latest version
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
    scid = "1" + base64.b32encode(sha256(norm).digest()).decode("ascii").lower()[:24]
    id_parts.pop()
    id_parts.append(scid)
    upd_id = ":".join(id_parts)
    return upd_id, json.loads(json.dumps(document).replace(doc_id, upd_id))


def eddsa_sign(document: dict, sk: VerificationMethod) -> dict:
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": document["id"] + "#" + sk.kid,
        "created": format_datetime(datetime.now(timezone.utc)),
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
    doc_dir = await auto_generate_did(
        "example.com", KeyAlgorithm(name="ed25519"), pass_key="password", scid_ver=1
    )
    # gen v2
    with open(doc_dir.joinpath("did.json")) as infile:
        doc = json.load(infile)
    doc["alsoKnownAs"] = ["did:web:example.com"]
    with open(doc_dir.joinpath("did.json"), "w") as outfile:
        json.dump(doc, outfile)
    doc = await update_document(doc_dir, pass_key="password")
    # gen v3
    doc["alsoKnownAs"] = ["did:web:sub.example.com"]
    with open(doc_dir.joinpath("did.json"), "w") as outfile:
        json.dump(doc, outfile)
    doc = await update_document(doc_dir, pass_key="password")


asyncio.run(demo())
