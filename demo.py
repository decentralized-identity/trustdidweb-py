import asyncio

from pathlib import Path
from typing import Tuple
from sys import argv

import aries_askar

from did_tdw import (
    DocumentState,
    HISTORY_FILENAME,
    add_auth_key,
    genesis_document,
    load_history_path,
    provision_did,
    # resolve_did_history,
    update_document_state,
    write_document_state,
)
from did_tdw.proof import AskarSigningKey, SigningKey


STORE_FILENAME = "keys.sqlite"


async def auto_generate_did(
    domain: str, key_alg: str, pass_key: str
) -> Tuple[Path, DocumentState, SigningKey]:
    key = aries_askar.Key.generate(key_alg)
    kid = "#" + key.get_jwk_thumbprint()
    print(f"Generated inception key ({key_alg}): {kid}")
    sk = AskarSigningKey(key, kid)
    genesis = genesis_document(domain, [sk])
    doc_path, state = await provision_did(genesis, sk)

    sk._kid = state.document_id + sk._kid
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_path}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(sk.kid, sk.key)
    await store.close()

    return (doc_path, state, sk)


async def demo(domain: str):
    pass_key = "password"
    (doc_dir, state, vm) = await auto_generate_did(domain, "ed25519", pass_key=pass_key)
    created = state.timestamp

    # gen v2 - add external controller
    ctl_id = "did:example:controller"
    doc = state.document_copy()
    doc["controller"] = [doc["id"], ctl_id]
    store_path = doc_dir.joinpath(STORE_FILENAME)
    ctl_sk = aries_askar.Key.generate("ed25519")
    ctl_vm = AskarSigningKey(ctl_sk, ctl_id + "#" + ctl_sk.get_jwk_thumbprint())
    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)
    async with store.session() as session:
        await session.insert_key(ctl_vm.kid, ctl_vm.key)
    await store.close()
    add_auth_key(doc, ctl_vm)
    state = update_document_state(state, doc, vm)  # sign with genesis key
    write_document_state(doc_dir, state)

    # gen v3 - add services
    doc = state.document_copy()
    doc["@context"].extend(
        [
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ]
    )
    doc["service"] = [
        {
            "id": doc["id"] + "#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": f"https://{domain}",
        },
        {
            "id": doc["id"] + "#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": f"https://{domain}/.well-known/whois.jsonld",
        },
    ]
    state = update_document_state(state, doc, ctl_vm)  # sign with controller key
    write_document_state(doc_dir, state)

    # verify history
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    check_state, meta = await load_history_path(history_path, verify_proofs=True)
    assert check_state == state
    assert meta.created == created
    assert meta.updated == state.timestamp
    assert meta.deactivated == False
    assert meta.version_id == 3


#     # test resolver
#     async with aiofiles.open(history_path) as history:
#         resolution = await resolve_did_history(doc["id"], history)
#     assert resolution.document == state.document
#     assert resolution.document_metadata["created"] == format_datetime(created)
#     assert resolution.document_metadata["updated"] == state.timestamp_raw
#     assert resolution.document_metadata["deactivated"] == False
#     assert resolution.document_metadata["versionId"] == "3"
#     async with aiofiles.open(history_path) as history:
#         resolution = await resolve_did_history(doc["id"], history, version_id=2)
#     assert resolution.document_metadata["versionId"] == "2"


# async def test_resolve():
#     print(await resolve_did("did:webnext:anywhy.ca:scid"))

if __name__ == "__main__":
    if len(argv) > 1:
        domain = argv[1]
    else:
        domain = "domain.example"
    asyncio.run(demo(domain))

# asyncio.run(test_resolve())
