"""Resolution of did:tdw DIDs."""

import argparse
import asyncio
import json
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import aiofiles
import aiohttp

from did_history.did_url import DIDUrl
from did_history.resolver import (
    DereferencingResult,
    ResolutionError,
    ResolutionResult,
    dereference_fragment,
    normalize_services,
    reference_map,
    resolve_history,
)

from .const import HISTORY_FILENAME, METHOD_NAME
from .proof import verify_all


def did_history_url(didurl: DIDUrl) -> str:
    """Determine the URL of the DID history file from a did:tdw DID URL."""
    id_parts = didurl.identifier.split(":")[1:]
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


def extend_document_services(document: dict, access_url: str):
    """Add the implicit services to a DID document, where not defined."""
    document["service"] = normalize_services(document)
    pos = access_url.rfind("/")
    if pos <= 0:
        raise ValueError(f"Invalid access URL: {access_url}")
    base_url = access_url[: pos + 1]
    ref_map = reference_map(document)
    doc_id = document["id"]

    if doc_id + "#files" not in ref_map["service"]:
        document["service"].append(
            {
                # FIXME will need to add @context if not provided already
                "id": doc_id + "#files",
                "type": "PathResolution",
                "serviceEndpoint": base_url,
            }
        )

    if doc_id + "#whois" not in ref_map["service"]:
        document["service"].append(
            {
                "@context": "https://identity.foundation/linked-vp/contexts/v1",
                "id": doc_id + "#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": base_url + "whois.vc",
            }
        )


def _find_service(document: dict, name: str) -> Optional[dict]:
    if name.startswith("#"):
        name = document["id"] + name
    ref_map = reference_map(document)
    return ref_map.get("service", {}).get(name)


async def resolve_did(
    did: Union[DIDUrl, str],
    *,
    local_history: Optional[Path] = None,
    version_id: Union[int, str, None] = None,
    version_time: Union[datetime, str, None] = None,
    add_implicit: bool = True,
    resolve_url: Optional[Callable[[str], Awaitable[AsyncIterator[str]]]] = None,
) -> ResolutionResult:
    """Resolve a did:tdw DID or DID URL.

    Resolution parameters within a DID URL are not applied.
    """
    didurl = DIDUrl.decode(did) if isinstance(did, str) else did
    url = did_history_url(didurl)
    if local_history:
        fetch_history = aiofiles.open(local_history)
    else:
        fetch_history = (resolve_url or _resolve_url)(url)
    try:
        async with fetch_history as content:
            result = await resolve_history(
                didurl.did,
                content,
                version_id=version_id,
                version_time=version_time,
                verify_state=verify_all,
            )
    except ValueError as err:
        return ResolutionResult(
            resolution_metadata=ResolutionError(
                "notFound", f"Error fetching DID history: {str(err)}"
            ).serialize()
        )
    if result.document and add_implicit:
        extend_document_services(result.document, url)
    return result


def _resolve_relative_ref_to_url(document: dict, service: str, relative_ref: str) -> str:
    svc = _find_service(document, f"#{service}")
    if svc:
        endpt = svc.get("serviceEndpoint")
        if isinstance(endpt, str):
            return urllib.parse.urljoin(endpt, relative_ref.removeprefix("/"))


async def _resolve_relative_ref(
    document: dict, service: str, relative_ref: str
) -> DereferencingResult:
    url = _resolve_relative_ref_to_url(document, service, relative_ref)
    if not url:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError(
                "notFound", "Unable to resolve relative path"
            ).serialize()
        )
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as req:
                req.raise_for_status()
                # FIXME binary content?
                content = await req.text()
                return DereferencingResult(
                    content=content,
                    # FIXME add content type
                    content_metadata={},
                    dereferencing_metadata={},
                )
        except aiohttp.ClientError as err:
            return DereferencingResult(
                dereferencing_metadata=ResolutionError(
                    "notFound", f"Error fetching relative path: {str(err)}"
                ).serialize()
            )


async def resolve(didurl: str, *, local_history: Optional[Path] = None) -> dict:
    """Resolve a did:tdw DID URL, applying any included DID resolution parameters."""
    try:
        didurl = DIDUrl.decode(args.didurl)
    except ValueError as err:
        return ResolutionResult(
            resolution_metadata=ResolutionError("invalidDid", str(err)).serialize()
        ).serialize()

    query = didurl.query_dict
    relative_ref = query.get("relativeRef")
    service_name = query.get("service")
    version_id = query.get("versionId")
    version_time = query.get("versionTime")
    # FIXME reject unknown query parameters?

    if didurl.path:
        # if service_name or relative_ref: invalid?
        service_name = "files"
        relative_ref = didurl.path

    result = await resolve_did(
        didurl.root,
        local_history=local_history,
        version_id=version_id,
        version_time=version_time,
    )

    if service_name and relative_ref and result.document:
        result = await _resolve_relative_ref(result.document, service_name, relative_ref)
    elif didurl.fragment and result.document:
        result = dereference_fragment(result.document, didurl.fragment)
    # FIXME relative_ref + fragment combination?

    return result.serialize()


@asynccontextmanager
async def _resolve_url(url: str) -> AsyncIterator[str]:
    try:
        async with aiohttp.ClientSession() as session, session.get(url) as req:
            req.raise_for_status()
            return req.content
    except aiohttp.ClientError as err:
        raise ValueError(str(err)) from None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:tdw DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("--accept", help="specify the MIME type(s) to accept")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    result = asyncio.run(resolve(args.didurl, local_history=args.file))

    print(json.dumps(result, indent=2))
