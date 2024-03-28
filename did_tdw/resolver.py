import asyncio

from sys import argv

from did_tdw import DIDUrl, resolve_did

if __name__ == "__main__":
    if len(argv) < 2:
        raise RuntimeError("Missing DID URL to resolve")

    didurl = DIDUrl.decode(argv[1])
    if didurl.path or didurl.fragment:
        raise RuntimeError("Dereferencing not yet supported")

    query = didurl.query_dict
    version_id = query.get("versionId")
    version_time = query.get("versionTime")

    result = asyncio.run(resolve_did(didurl.root))
    print(result)
