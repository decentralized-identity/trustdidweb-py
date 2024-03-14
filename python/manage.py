import asyncio
import json

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Generator, Optional, Tuple, Union

import aries_askar
import dag_json
import jsoncanon
import jsonpatch

from base58 import b58encode
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
    doc_v0_str = genesis_document(domain, [sk])
    doc_v0 = json.loads(doc_v0_str)
    cid_v0_obj = derive_version_cid(doc_v0)
    cid_v0 = cid_v0_obj.encode()

    scid = derive_scid(cid_v0_obj, scid_ver=scid_ver)
    print(f"Generated SCID: {scid}")

    doc_id = f"did:{METHOD}:{domain}:{scid}"
    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)
    write_document(doc_v0, None, doc_dir, cid=cid_v0)

    doc_v1 = json.loads(doc_v0_str.replace(PLACEHOLDER, scid))
    doc_v1["versionId"] = 1
    doc_v1["previousHash"] = cid_v0

    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(sk.kid, sk.key)
    await store.close()

    # debug: checking the SCID derivation
    verify_scid(doc_v1)

    doc_v1["proof"] = eddsa_sign(doc_v1, sk)

    write_document(doc_v1, doc_v0, doc_dir)

    return doc_dir


def write_document(
    document: dict, prev_document: Optional[dict], doc_dir: Path, cid: str = None
):
    version = document["versionId"]
    updated = document["updated"]
    pretty = json.dumps(document, indent=2)
    if not cid:
        cid = derive_version_cid(document).encode()
    diff = jsonpatch.make_patch(prev_document, document).patch

    with open(doc_dir.joinpath(LOG_FILENAME), "a+") as out:
        print(json.dumps([cid, updated, diff]), file=out)
    with open(doc_dir.joinpath(f"did-v{version}.json"), "w") as out:
        print(pretty, file=out)
    if prev_document:
        with open(doc_dir.joinpath(f"did.json"), "w") as out:
            print(pretty, file=out)
    print(f"Wrote document v{version} to {doc_dir}")


def load_log(
    path: Union[str, Path], verify_hash: bool
) -> Generator[Tuple[str, list], None, None]:
    """This currently loads every document version into memory."""
    index = 0
    doc = None
    for line in open(path):
        if not line:
            continue
        parts = json.loads(line)
        if not isinstance(parts, list) or len(parts) != 3:
            raise RuntimeError("Invalid log: not parsable")
        (hash, updated, diff) = parts
        doc = jsonpatch.apply_patch(doc, diff, in_place=True)
        if doc.get("versionId") != index:
            raise RuntimeError("Invalid log: inconsistent version")
        if doc.get("updated") != updated:
            raise RuntimeError("Invalid log: update time mismatch")
        if verify_hash:
            check_hash = derive_version_cid(doc).encode()
            if check_hash != hash:
                raise RuntimeError("Invalid log: hash mismatch")
        yield (hash, doc.copy())
        index += 1
    if not index:
        raise RuntimeError("Invalid log: no entries")


async def update_document(dir_path: str, pass_key: str):
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
    *_, (latest_hash, latest_doc) = load_log(log_path, verify_hash=True)

    with open(doc_path) as infile:
        document = json.load(infile)
    doc_id = document.get("id")
    ver = document.get("versionId")
    if not isinstance(ver, int):
        raise RuntimeError("Invalid document version")
    if ver == latest_doc["versionId"]:
        # update version
        document["versionId"] += 1
    elif ver != latest_doc["versionId"] + 1:
        # accept updated version
        raise RuntimeError("Invalid document version")
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

    document["proof"] = eddsa_sign(document, sk)

    write_document(document, latest_doc, doc_dir)


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
        "versionId": 0,
    }
    for vm in keys:
        kid = "#" + vm.kid
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
    if "previousHash" in document:
        document["previousHash"] = CID.decode(document["previousHash"])
    norm = dag_json.encode(document)
    hash = sha256(norm).digest()
    return CID(base="base58btc", version=1, codec="dag-json", digest=("sha2-256", hash))


def derive_scid(cid: CID, scid_ver=1) -> str:
    if scid_ver != 1:
        raise RuntimeError("Only SCID version 1 is supported")
    return "1" + b58encode(bytes(cid.raw_digest))[:24].decode("ascii").lower()


def verify_scid(document: Union[dict, str]):
    if isinstance(document, str):
        doc_json = document
        document = json.loads(document)
    else:
        doc_json = json.dumps(document)
    doc_id = document.get("id")
    if not doc_id or not isinstance(doc_id, str) or not doc_id.startswith("did:"):
        raise RuntimeError("Missing or invalid document id")
    pfx_id, doc_scid = doc_id.rsplit(":", 1)
    scid_ver = int(doc_scid[:1])
    plc_id = f"{pfx_id}:{PLACEHOLDER}"
    doc_v0 = json.loads(doc_json.replace(doc_id, plc_id))
    del doc_v0["previousHash"]
    doc_v0["versionId"] = 0
    cid = derive_version_cid(doc_v0)
    scid = derive_scid(cid, scid_ver=scid_ver)
    if doc_scid != scid:
        raise RuntimeError("SCID mismatch")


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
    with open(doc_dir.joinpath("did.json")) as infile:
        doc = json.load(infile)
    doc["alsoKnownAs"] = ["did:web:example.com"]
    with open(doc_dir.joinpath("did.json"), "w") as outfile:
        json.dump(doc, outfile)
    await update_document(doc_dir, pass_key="password")


asyncio.run(demo())
