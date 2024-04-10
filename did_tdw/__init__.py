import json
import urllib.parse

from datetime import datetime
from pathlib import Path
from typing import Tuple, Union

import aiofiles
import aiohttp

from did_history.format import PLACEHOLDER
from did_history.loader import load_history
from did_history.resolver import ResolutionError, ResolutionResult, resolve_history
from did_history.state import DocumentMetadata, DocumentState
from multiformats import multibase, multicodec

from .did import DIDUrl
from .proof import SigningKey, eddsa_jcs_sign, verify_document_id, verify_all

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MKEY_CONTEXT = "https://w3id.org/security/multikey/v1"

METHOD_NAME = "tdw"

HISTORY_FILENAME = "did.log"


async def provision_did(
    document: Union[str, dict],
    sk: SigningKey,
    *,
    timestamp: datetime = None,
) -> Tuple[Path, DocumentState]:
    state = DocumentState.initial(
        params={"method": f"did:{METHOD_NAME}:1"},
        document=document,
        timestamp=timestamp,
    )
    doc_id = state.document_id
    print(f"Initialized document: {doc_id}")

    doc_dir = Path(doc_id)
    doc_dir.mkdir(exist_ok=False)

    state.proofs.append(eddsa_jcs_sign(state, sk, timestamp=state.timestamp))
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


async def load_history_path(
    path: Union[str, Path],
    *,
    version_id: int = None,
    version_time: datetime = None,
    verify_proofs: bool = True,
) -> Tuple[DocumentState, DocumentMetadata]:
    verify_state = verify_all if verify_proofs else verify_document_id
    async with aiofiles.open(path, "r") as history:
        return await load_history(
            history,
            version_id=version_id,
            version_time=version_time,
            verify_hash=True,
            verify_state=verify_state,
        )


def update_document_state(
    prev_state: DocumentState,
    document: dict,
    sk: SigningKey,
    params_update: dict = None,
    timestamp: Union[str, datetime] = None,
) -> DocumentState:
    state = prev_state.create_next(
        document, params_update=params_update, timestamp=timestamp
    )
    state.proofs.append(eddsa_jcs_sign(state, sk, timestamp=state.timestamp))
    return state


def genesis_document(domain: str, keys: list[SigningKey]) -> str:
    """
    Generate a standard genesis document from a set of verification keys.

    The exact format of this document may change over time.
    """
    doc = {
        "@context": [DID_CONTEXT, MKEY_CONTEXT],
        "id": f"did:{METHOD_NAME}:{domain}:{PLACEHOLDER}",
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


def did_history_url(didurl: DIDUrl) -> str:
    id_parts = didurl.identifier.split(":")
    if didurl.method != METHOD_NAME or not id_parts or "" in id_parts:
        raise ValueError("Invalid DID")
    host = urllib.parse.unquote(id_parts[0])
    if ":" in host:
        host, port_str = host.split(":", 1)
        if not port_str.isdecimal():
            raise ValueError("Invalid port specification")
        port = f":{port_str}"
    else:
        port = ""
    path = id_parts[1:] or (".well-known",)
    return "/".join((f"https://{host}{port}", *path, HISTORY_FILENAME))


async def resolve_did(
    did: Union[DIDUrl, str],
    *,
    local_history: Path = None,
    version_id: Union[int, str] = None,
    version_time: Union[datetime, str] = None,
) -> ResolutionResult:
    if isinstance(did, str):
        didurl = DIDUrl.decode(did)
    else:
        didurl = did
    url = did_history_url(didurl)
    if local_history:
        # FIXME catch read errors
        async with aiofiles.open(local_history, "r") as history:
            return await resolve_history(
                didurl.did,
                history,
                version_id=version_id,
                version_time=version_time,
                verify_state=verify_all,
            )
    else:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as req:
                    req.raise_for_status()
                    return await resolve_history(
                        didurl.did,
                        req.content,
                        version_id=version_id,
                        version_time=version_time,
                        verify_state=verify_all,
                    )
        except aiohttp.ClientError as err:
            return ResolutionResult(
                resolution_metadata=ResolutionError(
                    "notFound", f"Error fetching DID history: {str(err)}"
                ).serialize()
            )
