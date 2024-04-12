import argparse
import asyncio
import json

from pathlib import Path

from did_history.resolver import dereference_fragment
from did_tdw import DIDUrl, resolve_did, resolve_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:tdw DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("--accept", help="specify the MIME type(s) to accept")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    didurl = DIDUrl.decode(args.didurl)

    query = didurl.query_dict
    version_id = query.get("versionId")
    version_time = query.get("versionTime")
    # FIXME reject unknown query parameters?

    local_history = Path(args.file) if args.file else None
    result = asyncio.run(
        resolve_did(
            didurl.root,
            local_history=local_history,
            version_id=version_id,
            version_time=version_time,
        )
    )

    if didurl.path and result.document:
        result = asyncio.run(resolve_path(result.document, didurl.path))
    if didurl.fragment and result.document:
        result = dereference_fragment(result.document, didurl.fragment)

    print(json.dumps(result.serialize(), indent=2))
