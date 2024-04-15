import argparse
import asyncio
import json

from datetime import datetime
from pathlib import Path
from typing import Tuple, Union


from did_history.format import SCID_PLACEHOLDER
from did_history.state import DocumentState
from multiformats import multibase, multicodec

from .history import METHOD_NAME, write_document_state
from .proof import SigningKey, eddsa_jcs_sign


DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"


def genesis_document(domain: str, keys: list[SigningKey]) -> str:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    doc = {
        "@context": [DID_CONTEXT, MKEY_CONTEXT],
        "id": f"did:{METHOD_NAME}:{domain}:{SCID_PLACEHOLDER}",
        "authentication": [],
        "verificationMethod": [],
    }
    for vm in keys:
        add_auth_key(doc, vm)
    return json.dumps(doc, indent=2)


def add_auth_key(document: dict, sk: SigningKey):
    if sk.algorithm == "ed25519":
        pk_codec = "ed25519-pub"
    else:
        raise ValueError(f"Unsupported signing key type: {sk.algorithm}")
    mkey = multibase.encode(multicodec.wrap(pk_codec, sk.public_key_bytes), "base58btc")
    kid = sk.kid
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


async def provision_did(
    document: Union[str, dict],
    sk: SigningKey,
    *,
    params: dict = None,
    timestamp: datetime = None,
    scid_length: int = None,
) -> Tuple[Path, DocumentState]:
    if not params:
        params = {}
    method = f"did:{METHOD_NAME}:1"
    if "method" in params and params["method"] != method:
        raise ValueError("Cannot override 'method' parameter")
    params["method"] = method
    state = DocumentState.initial(
        params=params, document=document, timestamp=timestamp, scid_length=scid_length
    )
    doc_id = state.document_id
    print(f"Initialized document: {doc_id}")

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    state.proofs.append(eddsa_jcs_sign(state, sk, timestamp=state.timestamp))
    write_document_state(doc_dir, state)

    return doc_dir, state
