import argparse
import asyncio

from pathlib import Path

from did_history.resolver import dereference
from did_tdw import DIDUrl, load_history_path, resolve_did

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="resolve a did:tdw DID URL")
    parser.add_argument("-f", "--file", help="the path to a local DID history file")
    parser.add_argument("--accept", help="specify the MIME type(s) to accept")
    parser.add_argument("didurl", help="the DID URL to resolve")
    args = parser.parse_args()

    didurl = DIDUrl.decode(args.didurl)
    if didurl.path:
        raise RuntimeError("Path dereferencing not yet supported")

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

    if didurl.fragment and result.document:
        result = dereference(result.document, didurl.fragment)

    print(result)
