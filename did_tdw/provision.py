import argparse
import asyncio
import base64
import json
import re

from copy import deepcopy
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Tuple, Union

import aries_askar
import jsoncanon

from did_history.did import SCID_PLACEHOLDER, DIDUrl
from did_history.state import DocumentState
from multiformats import multibase, multicodec

from .const import ASKAR_STORE_FILENAME, METHOD_NAME
from .history import write_document_state
from .proof import AskarSigningKey, VerifyingKey, eddsa_jcs_sign, verify_document_id


DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
DOMAIN_PATTERN = re.compile("^([a-zA-Z0-9%_\-]+\.)+[a-zA-Z0-9%_\.\-]{2,}$")


async def auto_generate_did(
    placeholder_id: str,
    key_alg: str,
    pass_key: str,
    *,
    params: dict = None,
    scid_length: int = None,
) -> Tuple[Path, DocumentState, AskarSigningKey]:
    sk = AskarSigningKey(aries_askar.Key.generate(key_alg))
    vm = encode_verification_method(sk, placeholder_id)
    genesis = genesis_document(placeholder_id, [vm])
    state = provision_did(genesis, params=params, scid_length=scid_length)
    doc_id = state.document_id
    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    sk.kid = doc_id + vm["id"].removeprefix(placeholder_id)
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir}/{ASKAR_STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(sk.kid, sk.key)
    await store.close()

    state.proofs.append(eddsa_jcs_sign(state, sk, timestamp=state.timestamp))
    write_document_state(doc_dir, state)

    return (doc_dir, state, sk)


def encode_verification_method(vk: VerifyingKey, controller: str = None) -> dict:
    if vk.algorithm == "ed25519":
        pk_codec = "ed25519-pub"
    else:
        raise ValueError(f"Unsupported signing key type: {vk.algorithm}")
    mkey = multibase.encode(multicodec.wrap(pk_codec, vk.public_key_bytes), "base58btc")
    keydef = {
        "type": "Multikey",
        "publicKeyMultibase": mkey,
    }
    kid = vk.kid
    if not kid:
        kid = "#" + (
            base64.urlsafe_b64encode(sha256(jsoncanon.canonicalize(keydef)).digest())
            .decode("ascii")
            .rstrip("=")
        )
    fpos = kid.find("#")
    if fpos < 0:
        raise RuntimeError("Missing fragment in verification method ID")
    elif fpos > 0:
        controller = kid[:fpos]
    else:
        controller = controller or ""
        kid = controller + kid
    return {"id": kid, "controller": controller, **keydef}


def genesis_document(placeholder_id: str, auth_keys: list[dict]) -> dict:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    # FIXME check format of placeholder ID
    return {
        "@context": [DID_CONTEXT, MKEY_CONTEXT],
        "id": placeholder_id,
        "authentication": [k["id"] for k in auth_keys],
        "verificationMethod": [deepcopy(k) for k in auth_keys],
    }


def provision_did(
    document: Union[str, dict],
    *,
    params: dict = None,
    timestamp: datetime = None,
    scid_length: int = None,
) -> DocumentState:
    if not params:
        params = {}
    method = f"did:{METHOD_NAME}:1"
    if "method" in params and params["method"] != method:
        raise ValueError("Cannot override 'method' parameter")
    params["method"] = method
    return DocumentState.initial(
        params=params, document=document, timestamp=timestamp, scid_length=scid_length
    )


def normalize_provision_id(domain_or_did: str) -> str:
    if SCID_PLACEHOLDER not in domain_or_did:
        # must be a domain
        if ":" in domain_or_did:
            raise ValueError("Missing SCID placeholder in DID")
        if not DOMAIN_PATTERN.match(domain_or_did):
            raise ValueError(f"Invalid domain name: {domain_or_did}")
        return f"{domain_or_did}:{SCID_PLACEHOLDER}"
    if not domain_or_did.startswith("did:"):
        domain_or_did = f"did:{METHOD_NAME}:{domain_or_did}"
    verify_document_id(domain_or_did.replace(SCID_PLACEHOLDER, "__SCID__"), "__SCID__")
    return domain_or_did


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="provision a new did:tdw DID")
    # parser.add_argument(
    #     "-i", "--input", help="the path to the genesis DID document (did.json)"
    # )
    # parser.add_argument("-o", "--output", help="the output path (did.jsonl)")
    parser.add_argument(
        "--hash", help="the name of the hash function (default sha-256)"
    )
    parser.add_argument(
        "--length", type=int, help="the length of the SCID (default 28)"
    )
    parser.add_argument("did", help="the domain name or DID to provision")
    args = parser.parse_args()

    placeholder_id = normalize_provision_id(args.did)
    params = {}
    if args.hash:
        params["hash"] = args.hash
    doc_dir, state, _ = asyncio.run(
        auto_generate_did(
            placeholder_id,
            "ed25519",
            "password",
            params=params,
            scid_length=args.length,
        )
    )
    doc_path = doc_dir.joinpath("did.json")
    with open(doc_path, "w") as out:
        print(
            json.dumps(state.document),
            file=out,
        )
    print(f"Provisioned DID in", doc_dir)
