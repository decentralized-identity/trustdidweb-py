import argparse
import asyncio
import json

from pathlib import Path

from did_history.resolver import dereference_fragment
from did_tdw import DIDUrl, resolve_did, resolve_relative_ref

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:tdw DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("--accept", help="specify the MIME type(s) to accept")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    didurl = DIDUrl.decode(args.didurl)

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

    local_history = Path(args.file) if args.file else None
    result = asyncio.run(
        resolve_did(
            didurl.root,
            local_history=local_history,
            version_id=version_id,
            version_time=version_time,
        )
    )

    if service_name and relative_ref and result.document:
        result = asyncio.run(
            resolve_relative_ref(result.document, service_name, relative_ref)
        )
    elif didurl.fragment and result.document:
        result = dereference_fragment(result.document, didurl.fragment)
    # FIXME relative_ref + fragment combination?

    print(json.dumps(result.serialize(), indent=2))
