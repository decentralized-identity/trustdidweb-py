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

from did_history.did import SCID_PLACEHOLDER
from did_history.format import format_hash
from did_history.state import DocumentState, get_hash_fn

from .const import ASKAR_STORE_FILENAME, HISTORY_FILENAME, METHOD_NAME, METHOD_VERSION
from .history import load_history_path, write_document_state
from .proof import (
    AskarSigningKey,
    VerifyingKey,
    check_document_id_format,
    di_jcs_sign,
)


DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
DOMAIN_PATTERN = re.compile(r"^([a-zA-Z0-9%_\-]+\.)+[a-zA-Z0-9%_\.\-]{2,}$")


async def auto_provision_did(
    domain_path: str,
    key_alg: str,
    pass_key: str,
    *,
    extra_params: dict = None,
) -> Tuple[Path, DocumentState, AskarSigningKey]:
    update_key = AskarSigningKey.generate(key_alg)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{domain_path}"
    genesis = genesis_document(placeholder_id)
    params = deepcopy(extra_params) if extra_params else {}
    params["updateKeys"] = [update_key.multikey]
    if params.get("prerotation"):
        next_key = AskarSigningKey.generate(key_alg)
        hash_fn = get_hash_fn(params)
        next_key_hash = format_hash(hash_fn(next_key.multikey.encode("utf-8")))
        params["nextKeyHashes"] = [next_key_hash]
    else:
        next_key = None
        next_key_hash = None
    state = provision_did(genesis, params=params)
    doc_id = state.document_id
    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir}/{ASKAR_STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(update_key.kid, update_key.key)
        if next_key:
            await session.insert_key(
                next_key.kid, next_key.key, tags={"hash": next_key_hash}
            )
    await store.close()

    state.proofs.append(
        di_jcs_sign(
            state,
            update_key,
            timestamp=state.timestamp,
        )
    )
    write_document_state(doc_dir, state)

    # verify log
    await load_history_path(doc_dir.joinpath(HISTORY_FILENAME))

    return (doc_dir, state, update_key)


def encode_verification_method(vk: VerifyingKey, controller: str = None) -> dict:
    keydef = {
        "type": "Multikey",
        "publicKeyMultibase": vk.multikey,
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


def genesis_document(placeholder_id: str) -> dict:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    # FIXME check format of placeholder ID
    return {
        "@context": [DID_CONTEXT, MKEY_CONTEXT],
        "id": placeholder_id,
    }


def provision_did(
    document: Union[str, dict],
    *,
    params: dict = None,
    timestamp: datetime = None,
) -> DocumentState:
    if not params:
        params = {}
    method = f"did:{METHOD_NAME}:{METHOD_VERSION}"
    if "method" in params and params["method"] != method:
        raise ValueError("Cannot override 'method' parameter")
    params["method"] = method
    return DocumentState.initial(params=params, document=document, timestamp=timestamp)


def normalize_placeholder_id(domain_path: str) -> str:
    if domain_path.startswith("did:"):
        placeholder_id = domain_path
    else:
        placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{domain_path}"
    check_document_id_format(
        placeholder_id.replace(SCID_PLACEHOLDER, "__SCID__"), "__SCID__"
    )
    return placeholder_id


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="provision a new did:tdw DID")
    parser.add_argument(
        "--auto",
        action="store_true",
        help="automatically provision a new key using a local Askar store",
    )
    parser.add_argument(
        "--algorithm",
        help="the signing key algorithm (default ed25519)",
    )
    parser.add_argument(
        "--hash", help="the name of the hash function (default sha-256)"
    )
    parser.add_argument(
        "domain-path", help="the domain name and optional path components"
    )
    args = parser.parse_args()

    if not args.auto:
        raise SystemExit("Only automatic provisioning (--auto) is currently supported")

    placeholder_id = normalize_placeholder_id(args.domain_path)
    params = {}
    if args.hash:
        params["hash"] = args.hash

    try:
        doc_dir, state, _ = asyncio.run(
            auto_provision_did(
                placeholder_id,
                args.algorithm or "ed25519",
                "password",
                params=params,
            )
        )
    except ValueError as err:
        raise SystemExit(f"Provisioning failed: {err}")

    doc_path = doc_dir.joinpath("did.json")
    with open(doc_path, "w") as out:
        print(
            json.dumps(state.document, indent=2),
            file=out,
        )
    print("Provisioned DID in", doc_dir)
