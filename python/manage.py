import asyncio
import base64
import json

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Union

import aries_askar
import dag_json
import jsoncanon

from base58 import b58encode
from multiformats import CID

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
JWS_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"
METHOD = "webnext"


@dataclass
class KeyAlgorithm:
    name: str


async def auto_generate_did(key_alg: KeyAlgorithm, pass_key: str, scid_ver=1):
    key = aries_askar.Key.generate(key_alg.name)
    kid = key.get_jwk_thumbprint()
    print(f"Generated inception key ({key_alg.name}): {kid}")
    doc_v0 = genesis_document([key])
    cid_v0 = derive_version_cid(doc_v0)
    scid = derive_scid(cid_v0, scid_ver=scid_ver)
    print(f"Generated SCID: {scid}")
    doc_id = f"did:{METHOD}:{scid}"
    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)
    doc_v1 = json.loads(doc_v0.replace("{{SCID}}", scid))
    doc_v1["versionId"] = 1
    doc_v1["previousHash"] = cid_v0.encode()
    cid_v1 = derive_version_cid(doc_v1).encode()

    with open(doc_dir.joinpath("did.json.log"), "w") as out:
        print(
            json.dumps(
                {
                    "hash": cid_v1,
                    "versionDate": doc_v1["updated"],
                    "versionId": 1,
                }
            ),
            file=out,
        )

    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir.name}/keys.sqlite", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(kid, key)
    await store.close()

    # debug: checking the SCID derivation
    verify_scid(doc_v1)

    doc_v1["proof"] = [eddsa_sign(doc_v1, key, kid)]

    pretty = json.dumps(doc_v1, indent=2)
    with open(doc_dir.joinpath(f"did-{cid_v1}.json"), "w") as out:
        print(pretty, file=out)
    with open(doc_dir.joinpath(f"did-v1.json"), "w") as out:
        print(pretty, file=out)
    with open(doc_dir.joinpath(f"did.json"), "w") as out:
        print(pretty, file=out)

    print(f"Wrote document to {doc_dir}")


def genesis_document(keys: list[aries_askar.Key]) -> str:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    now = datetime.now().isoformat(timespec="seconds")
    doc = {
        "@context": [DID_CONTEXT, JWS_CONTEXT],
        "id": "did:webnext:{{SCID}}",
        "created": now,
        "updated": now,
        "authentication": [],
        "verificationMethod": [],
        "previousHash": "",
        "versionId": 0,
    }
    for key in keys:
        kid = "#" + key.get_jwk_thumbprint()
        doc["authentication"].append(kid)
        doc["verificationMethod"].append(
            {
                "id": kid,
                "publicKeyJwk": json.loads(key.get_jwk_public()),
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
    plc_id = pfx_id + ":{{SCID}}"
    doc_v0 = json.loads(doc_json.replace(doc_id, plc_id))
    doc_v0["previousHash"] = ""
    doc_v0["versionId"] = 0
    cid = derive_version_cid(doc_v0)
    scid = derive_scid(cid, scid_ver=scid_ver)
    if doc_scid != scid:
        raise RuntimeError("SCID mismatch")


def eddsa_sign(document: dict, key: aries_askar.Key, kid: str) -> dict:
    proof = {
        "type": "DataIntegrityProof",
        "ciphersuite": "eddsa-jcs-2022",
        "verificationMethod": kid,
        "proofPurpose": "authentication",
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    data_hash = sha256(jsoncanon.canonicalize(document)).digest()
    options_hash = sha256(jsoncanon.canonicalize(proof)).digest()
    sig_input = data_hash + options_hash
    proof["signature"] = (
        base64.urlsafe_b64encode(key.sign_message(sig_input))
        .decode("ascii")
        .rstrip("=")
    )
    return proof


asyncio.run(
    auto_generate_did(KeyAlgorithm(name="ed25519"), pass_key="password", scid_ver=1)
)
