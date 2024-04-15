import asyncio
import json

from datetime import datetime
from pathlib import Path
from typing import Tuple
from sys import argv

import aries_askar

from did_history.date_utils import make_timestamp
from did_history.state import DocumentState
from did_tdw.history import (
    HISTORY_FILENAME,
    load_history_path,
    update_document_state,
    write_document_state,
)
from did_tdw.proof import AskarSigningKey, SigningKey, eddsa_jcs_sign_raw
from did_tdw.provision import (
    add_auth_key,
    genesis_document,
    provision_did,
)


STORE_FILENAME = "keys.sqlite"


async def auto_generate_did(
    domain: str,
    key_alg: str,
    pass_key: str,
    *,
    params: dict = None,
    scid_length: int = None,
) -> Tuple[Path, DocumentState, SigningKey]:
    key = aries_askar.Key.generate(key_alg)
    kid = "#" + key.get_jwk_thumbprint()
    print(f"Generated inception key ({key_alg}): {kid}")
    sk = AskarSigningKey(key, kid)
    genesis = genesis_document(domain, [sk])
    doc_dir, state = await provision_did(
        genesis, sk, params=params, scid_length=scid_length
    )
    log_document_state(doc_dir, state)

    sk._kid = state.document_id + sk._kid
    store = await aries_askar.Store.provision(
        f"sqlite://{doc_dir}/{STORE_FILENAME}", pass_key=pass_key
    )
    async with store.session() as session:
        await session.insert_key(sk.kid, sk.key)
    await store.close()

    return (doc_dir, state, sk)


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
    vc["proof"] = eddsa_jcs_sign_raw(vc, sk, "assertionMethod")
    return {
        "@context": "https://identity.foundation/.well-known/did-configuration/v1",
        "linked_dids": [vc],
    }


def log_document_state(doc_dir: Path, state: DocumentState):
    pretty = json.dumps(state.document, indent=2)
    with open(doc_dir.joinpath(f"did-v{state.version_id}.json"), "w") as out:
        print(pretty, file=out)

    print(f"Wrote document v{state.version_id} to {doc_dir}")


async def demo(domain: str, *, params: dict = None, scid_length: int = None):
    pass_key = "password"
    (doc_dir, state, sk) = await auto_generate_did(
        domain, "ed25519", pass_key=pass_key, params=params, scid_length=scid_length
    )
    created = state.timestamp

    # gen v2 - add external controller
    ctl_id = "did:example:controller"
    doc = state.document_copy()
    doc["controller"] = [doc["id"], ctl_id]
    store_path = doc_dir.joinpath(STORE_FILENAME)
    ctl_key = aries_askar.Key.generate("ed25519")
    ctl_sk = AskarSigningKey(ctl_key, ctl_id + "#" + ctl_key.get_jwk_thumbprint())
    store = await aries_askar.Store.open(f"sqlite://{store_path}", pass_key=pass_key)
    async with store.session() as session:
        await session.insert_key(ctl_sk.kid, ctl_sk.key)
    await store.close()
    add_auth_key(doc, ctl_sk)
    state = update_document_state(state, doc, sk)  # sign with genesis key
    write_document_state(doc_dir, state)
    log_document_state(doc_dir, state)

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
    doc["assertionMethod"] = [doc["authentication"][0]]  # enable VC signing
    state = update_document_state(state, doc, ctl_sk)  # sign with controller key
    write_document_state(doc_dir, state)
    log_document_state(doc_dir, state)

    # verify history
    history_path = doc_dir.joinpath(HISTORY_FILENAME)
    check_state, meta = await load_history_path(history_path, verify_proofs=True)
    assert check_state == state
    assert meta.created == created
    assert meta.updated == state.timestamp
    assert meta.deactivated == False
    assert meta.version_id == 3

    # output did configuration
    did_conf = create_did_configuration(
        doc["id"],
        f"https://{domain}",
        sk,
    )
    with open(doc_dir.joinpath("did-configuration.json"), "w") as outdc:
        print(json.dumps(did_conf, indent=2), file=outdc)
    print("Wrote did-configuration.json")


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
    asyncio.run(demo(domain, params={"hash": "sha3-256"}))
