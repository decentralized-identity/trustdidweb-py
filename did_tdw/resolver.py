import argparse
import asyncio
import json

from pathlib import Path

from did_history.resolver import ResolutionError, ResolutionResult, dereference_fragment
from did_tdw import DIDUrl, resolve_did, resolve_relative_ref


async def resolve(didurl: str, *, local_history: Path = None) -> dict:
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
        result = await resolve_relative_ref(result.document, service_name, relative_ref)
    elif didurl.fragment and result.document:
        result = dereference_fragment(result.document, didurl.fragment)
    # FIXME relative_ref + fragment combination?

    return result.serialize()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:tdw DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("--accept", help="specify the MIME type(s) to accept")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    result = asyncio.run(resolve(args.didurl, local_history=args.file))

    print(json.dumps(result, indent=2))
