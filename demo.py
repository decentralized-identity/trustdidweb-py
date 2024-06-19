import asyncio
import json

from datetime import datetime
from pathlib import Path
from sys import argv
from time import perf_counter

import aries_askar

from did_history.did import SCID_PLACEHOLDER
from did_history.date_utils import make_timestamp
from did_history.state import DocumentState
from did_tdw.const import ASKAR_STORE_FILENAME, HISTORY_FILENAME
from did_tdw.history import (
    load_history_path,
    update_document_state,
    write_document_state,
)
from did_tdw.proof import AskarSigningKey, SigningKey, di_jcs_sign_raw
from did_tdw.provision import (
    auto_provision_did,
)


def create_did_configuration(
    did: str, origin: str, sk: SigningKey, timestamp: datetime = None
) -> dict:
    _, timestamp = make_timestamp(timestamp)
    vc = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://identity.foundation/.well-known/did-configuration/v1",
        ],
        "issuer": did,
        "validFrom": timestamp,
        # "validUntil":
        "type": ["VerifiableCredential", "DomainLinkageCredential"],
        "credentialSubject": {
            "id": did,
            "origin": origin,
        },
    }
    vc["proof"] = di_jcs_sign_raw(vc, sk, "assertionMethod")
    return {
        "@context": "https://identity.foundation/.well-known/did-configuration/v1",
        "linked_dids": [vc],
    }


def log_document_state(doc_dir: Path, state: DocumentState):
    pretty = json.dumps(state.document, indent=2)
    with open(doc_dir.joinpath(f"did-v{state.version_id}.json"), "w") as out:
        print(pretty, file=out)


async def demo(
    domain: str,
    *,
    key_alg: str = None,
    params: dict = None,
    scid_length: int = None,
    perf_check: bool = False,
):
    pass_key = "password"
    key_alg = key_alg or "ed25519"
    (doc_dir, state, genesis_key) = await auto_provision_did(
        f"did:tdw:{domain}:{SCID_PLACEHOLDER}",
        key_alg,
        pass_key=pass_key,
        extra_params=params,
        scid_length=scid_length,
    )
    print(f"Provisioned DID: {state.document_id}")
    log_document_state(doc_dir, state)
    created = state.timestamp
    store_path = doc_dir.joinpath(ASKAR_STORE_FILENAME)
    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)

    if state.prerotation:
        # generate replacement update key
        rotate_key_hash = state.next_key_hashes[0]
        next_update_key = AskarSigningKey.generate(key_alg)
        next_key_hash = state.generate_next_key_hash(next_update_key.multikey)
        async with store.session() as session:
            await session.insert_key(
                next_update_key.kid, next_update_key.key, tags={"hash": next_key_hash}
            )
            # fetch next update key by hash
            fetched = await session.fetch_all_keys(tag_filter={"hash": rotate_key_hash})
            if not fetched:
                raise ValueError(
                    f"Next update key not found in key store: {rotate_key_hash}"
                )
            update_key = AskarSigningKey(fetched[0].key)

        # rotate to next update key
        params_update = {
            "updateKeys": [update_key.multikey],
            "nextKeyHashes": [next_key_hash],
        }
        state = update_document_state(state, genesis_key, params_update=params_update)
        write_document_state(doc_dir, state)
        log_document_state(doc_dir, state)
        print(f"Wrote document v{state.version_id}")
    else:
        update_key = genesis_key

    # add services
    doc = state.document_copy()
    auth_key = AskarSigningKey.generate("ed25519")
    auth_key.kid = doc["id"] + "#" + auth_key.multikey
    async with store.session() as session:
        await session.insert_key(auth_key.multikey, auth_key.key)
    doc = state.document_copy()
    doc["@context"].extend(
        [
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ]
    )
    doc["authentication"] = [auth_key.kid]
    doc["assertionMethod"] = [auth_key.kid]
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
    state = update_document_state(state, update_key, document_update=doc)
    write_document_state(doc_dir, state)
    log_document_state(doc_dir, state)
    print(f"Wrote document v{state.version_id}")

    await store.close()

    # verify history
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    check_state, meta = await load_history_path(history_path)
    assert check_state == state
    assert meta.created == created
    assert meta.updated == state.timestamp
    assert meta.deactivated is False
    if state.prerotation:
        assert meta.version_id == 3
    else:
        assert meta.version_id == 2

    # output did configuration
    did_conf = create_did_configuration(
        doc["id"],
        f"https://{domain}",
        genesis_key,
    )
    with open(doc_dir.joinpath("did-configuration.json"), "w") as outdc:
        print(json.dumps(did_conf, indent=2), file=outdc)
    print("Wrote did-configuration.json")

    # performance check
    if perf_check:
        start = perf_counter()
        for i in range(1000):
            doc["etc"] = i
            state = update_document_state(state, update_key, document_update=doc)
            write_document_state(doc_dir, state)
        dur = perf_counter() - start
        print(f"Update duration: {dur:0.2f}")

        start = perf_counter()
        (latest, meta) = await load_history_path(history_path)
        assert latest == state
        dur = perf_counter() - start
        print(f"Validate duration: {dur:0.2f}")


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


if __name__ == "__main__":
    if len(argv) > 1:
        domain = argv[1]
    else:
        domain = "domain.example"
    asyncio.run(
        demo(domain, key_alg="p384", params={"hash": "sha3-256", "prerotation": True})
    )
