from copy import deepcopy
from json import JSONDecodeError

import pytest

from did_history.format import HASH_FN_MAP, HashInfo
from did_history.state import DocumentState


def test_initial_document_state():
    # Valid
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:tdw:{SCID}:domain.example"}',
    )

    # Invalid json document string
    with pytest.raises(JSONDecodeError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:tdw:0.3",
            },
            document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:tdw:{SCID}:domain.example",}',
        )
    # Doc id is not a string
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:tdw:0.3",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": 10000,
            },
        )
    # No SCID placeholder
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:tdw:0.3",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:tdw:{NOTSCID}:domain.example\n",
            },
        )


def test_generate_entry_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )

    generated_hash = doc_state.generate_entry_hash()
    assert isinstance(generated_hash, str)

    hash_info = HashInfo(HASH_FN_MAP["sha3-256"], name="test")
    generated_hash = doc_state.generate_entry_hash(hash_info=hash_info)
    assert isinstance(generated_hash, str)


def test_check_version_id():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    doc_state.check_version_id()

    # Wrong version id
    doc_state.version_id = "1-QmacBLStXRknM45JGFGUnpcBUibBCvNYJEjyUeZcATVC34"
    with pytest.raises(ValueError):
        doc_state.check_version_id()


def test_generate_next_key_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    doc_state.generate_next_key_hash(
        multikey="z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )


def test_check_scid_derivation():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    doc_state.check_scid_derivation()

    # version number equals 1
    doc_state.version_number = 2
    with pytest.raises(ValueError):
        doc_state.check_scid_derivation()
    doc_state.version_number = 1
    doc_state.check_scid_derivation()

    # version id must equal scid
    last_version_id = doc_state.last_version_id
    doc_state.last_version_id = "2-QmUuhGnfMoW8P5JCMWUJi4Ns3WkHsStj2ZEhzpMU7PV8QK"
    with pytest.raises(ValueError):
        doc_state.check_scid_derivation()
    doc_state.last_version_id = last_version_id
    doc_state.check_scid_derivation()

    # Wrong timestamp
    timestamp_raw = doc_state.timestamp_raw
    doc_state.timestamp_raw = "2023-09-10T18:15:05Z"
    with pytest.raises(ValueError):
        doc_state.check_scid_derivation()
    doc_state.timestamp_raw = timestamp_raw
    doc_state.check_scid_derivation()


def test_create_next():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    assert isinstance(doc_state.create_next(), DocumentState)


def test_load_history_line():
    valid_line = {
        "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
        "versionTime": "2024-09-10T18:29:27Z",
        "parameters": {
            "prerotation": True,
            "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
            "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
            "method": "did:tdw:0.3",
            "scid": "QmVHduNq3ncp42Q7sS2Zo7EeiamEsdYnyUiipRaWK4Aw95",
        },
        "state": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:QmVHduNq3ncp42Q7sS2Zo7EeiamEsdYnyUiipRaWK4Aw95:domain.example",
        },
        "proof": [
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                "created": "2024-09-10T18:29:27Z",
                "proofPurpose": "authentication",
                "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
            }
        ],
    }

    DocumentState.load_history_line(
        valid_line,
        {},
    )

    # Invalid list length - no proof
    line = deepcopy(valid_line)
    del line["proof"]
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )

    # Invalid - Params isn't a dict
    line = deepcopy(valid_line)
    line["parameters"] = (
        '{"prerotation": True,"updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],"nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],"method": "did:tdw:0.3","scid": "QmXwpXEc44Rw8A7u7okUvsg3HC69JAKV6b3wX4thyV7nYe",}'
    )
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )


def test_load_history_line_with_prev_state():
    prev_state = DocumentState.load_history_line(
        {
            "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
            "versionTime": "2024-09-10T18:29:27Z",
            "parameters": {
                "prerotation": True,
                "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
                "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
                "method": "did:tdw:0.3",
                "scid": "QmVHduNq3ncp42Q7sS2Zo7EeiamEsdYnyUiipRaWK4Aw95",
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:tdw:QmVHduNq3ncp42Q7sS2Zo7EeiamEsdYnyUiipRaWK4Aw95:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:27Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
                }
            ],
        },
        {},
    )

    DocumentState.load_history_line(
        {
            "versionId": "2-QmVRDqG6kCetD54LEcSomsDm7uCpsHbQkdqk7V5J58aV33",
            "versionTime": "2024-09-10T18:29:28Z",
            "parameters": {
                "updateKeys": ["z6MkoSd9jDGV2hyJCb9GiskBPBTY3o4eNs3K9Vr8tCD5Lpkh"],
                "nextKeyHashes": ["QmdkSM2aqyk5Vfcqz4Bw6AKhp3WoFBSL85ydEqAan8UX8A"],
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:tdw:QmVHduNq3ncp42Q7sS2Zo7EeiamEsdYnyUiipRaWK4Aw95:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:28Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z3vmBNQrQME3R9Y1KgZZbmgpSwT4rwVUBVDwkfmzULADGRxosk2GqvVmGLVRmW8j2SV7zHN1UA97uc2pMM5x7X27N",
                }
            ],
        },
        prev_state=prev_state,
    )
