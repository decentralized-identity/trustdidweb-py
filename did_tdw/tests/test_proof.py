from datetime import datetime, timezone

import pytest

from aries_askar import Key as AskarKey

from did_history.state import DocumentState
from did_tdw.proof import (
    AskarSigningKey,
    check_document_id_format,
    di_jcs_sign,
    di_jcs_sign_raw,
    di_jcs_verify,
    verify_proofs,
)


@pytest.fixture()
def mock_document() -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ],
        "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
        "authentication": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
        "service": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com%3A5000",
            },
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": "https://example.com%3A5000/.well-known/whois.vc",
            },
        ],
        "verificationMethod": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
                "controller": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
                "type": "Multikey",
                "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
            }
        ],
        "assertionMethod": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
    }


@pytest.fixture()
def mock_document_state() -> DocumentState:
    return DocumentState(
        params={
            "prerotation": True,
            "updateKeys": ["z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun"],
            "nextKeyHashes": ["Qmbj4wLBmB8rj48svucmeffwDTDyt33s61w1iupwHLUfcn"],
            "method": "did:tdw:0.3",
            "scid": "Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6",
        },
        params_update={
            "prerotation": True,
            "updateKeys": ["z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun"],
            "nextKeyHashes": ["Qmbj4wLBmB8rj48svucmeffwDTDyt33s61w1iupwHLUfcn"],
            "method": "did:tdw:0.3",
            "scid": "Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6:domain.example",
        },
        timestamp=datetime(2024, 9, 17, 17, 29, 32, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:32Z",
        version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        version_number=1,
        last_version_id="Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
                "created": "2024-09-25T21:19:01Z",
                "proofPurpose": "authentication",
                "proofValue": "z2bmMT2A7JGE8A9MKtEuLWq6TQfs4VZA5qTfixYtBMwJmyWysFU9BUgATsLL6HB6RFVqZSvHLBaPRjN6S9WVLeSfo",
            }
        ],
    )


@pytest.fixture()
def mock_sk() -> AskarSigningKey:
    return AskarSigningKey(
        AskarKey.from_jwk(
            '{"crv":"Ed25519","kty":"OKP","x":"iWIGdqmPSeg8Ov89VzUrKuLD7pJ8_askEwJGE1R5Zqk","d":"RJDq2-dY85mW1bbDMcrXPObeL-Ud-b8MrPO-iqxajv0"}'
        )
    )


def test_jcs_sign_verify(mock_sk):
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:tdw:0.3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }
    proof = di_jcs_sign(mock_state, sk=mock_sk)
    di_jcs_verify(mock_state, proof, method)
    proof = di_jcs_sign(
        mock_state,
        sk=mock_sk,
        timestamp=datetime.now(),
    )
    di_jcs_verify(mock_state, proof, method)
    proof = di_jcs_sign(
        mock_state,
        sk=mock_sk,
        timestamp=datetime.now(),
        kid="kid",
    )
    di_jcs_verify(mock_state, proof, method)


def test_jcs_sign_raw(mock_document):
    result = di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("ed25519"),
        purpose="authentication",
        challenge="challenge",
    )
    assert isinstance(result, dict)
    di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("p256"),
        purpose="authentication",
        challenge="challenge",
    )
    di_jcs_sign_raw(
        mock_document,
        sk=AskarSigningKey.generate("p384"),
        purpose="authentication",
        challenge="challenge",
    )
    with pytest.raises(TypeError):
        di_jcs_sign_raw(
            mock_document,
            sk=AskarSigningKey.generate("bls12381g1g2"),
            purpose="authentication",
            challenge="challenge",
        )


def test_di_jcs_verify(mock_document_state, mock_sk):
    bad_proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkosXkYcPjPhWcvWbSxW26Lr3GqYEmqJXWj1mspB76Kqx8#z6MkosXkYcPjPhWcvWbSxW26Lr3GqYEmqJXWj1mspB76Kqx8",
        "created": "2024-09-10T22:31:17Z",
        "proofPurpose": "authentication",
        "proofValue": "zhLxMHk6oaVmoJ2Xo4Hw8QQG9RP4eNPuDg4co7ExcCXbe5sRgomLjCgQ9vevLVPWGar79iAh4t697jJ9iMYFNQ8r",
    }
    good_proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
        "created": "2024-09-25T21:19:01Z",
        "proofPurpose": "authentication",
        "proofValue": "z2bmMT2A7JGE8A9MKtEuLWq6TQfs4VZA5qTfixYtBMwJmyWysFU9BUgATsLL6HB6RFVqZSvHLBaPRjN6S9WVLeSfo",
    }
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }

    di_jcs_verify(mock_document_state, good_proof, method)

    with pytest.raises(ValueError):
        di_jcs_verify(mock_document_state, bad_proof, method)


VALID_DID = [
    "did:tdw:0000000000000000000000000000:mydomain.com",
    "did:tdw:0000000000000000000000000000:mydomain.com%3A500",
    "did:tdw:0000000000000000000000000000:mydomain.com%3A500:path",
    "did:tdw:0000000000000000000000000000:mydomain.com%3A500:path:extra",
    "did:tdw:0000000000000000000000000000:mydomain.com:path:extra",
]


@pytest.mark.parametrize("did", VALID_DID)
def test_valid_document_id(did: str):
    check_document_id_format(did, "0000000000000000000000000000")


INVALID_DID = [
    # missing did:
    "DID:tdw:0000000000000000000000000000.mydomain.com",
    # invalid method
    "did:other:0000000000000000000000000000.mydomain.com",
    # missing scid
    "did:tdw:domain.example",
    "did:tdw:domain.example:path",
    # missing tld
    "did:tdw:0000000000000000000000000000",
    # missing domain
    "did:tdw:0000000000000000000000000000.com",
    "did:tdw:mydomain.0000000000000000000000000000",
    "did:tdw:mydomain.com.0000000000000000000000000000",
    # duplicate
    "did:tdw:0000000000000000000000000000.mydomain.com:path:0000000000000000000000000000",
]


@pytest.mark.parametrize("did", INVALID_DID)
def test_invalid_document_id(did: str):
    with pytest.raises(ValueError):
        check_document_id_format(did, "0000000000000000000000000000")


def test_check_document_id_format():
    check_document_id_format(
        "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com",
        "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
    )
    # scid doesn't match
    with pytest.raises(ValueError):
        check_document_id_format(
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGY:example.com",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )
    # wrong did method (web)
    with pytest.raises(ValueError):
        check_document_id_format(
            "did:web:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )
    # no path
    with pytest.raises(ValueError):
        check_document_id_format(
            "did:web:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
            "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4",
        )


def test_verify_proofs(mock_document_state, mock_sk):
    verify_proofs(mock_document_state, None, is_final=False)

    prev_state = mock_document_state
    current_state = DocumentState(
        params={
            "prerotation": True,
            "updateKeys": ["z6MkmTNGEZUFRkfKd5TKooEGfdMqdokphHarKSngiPvvJdGR"],
            "nextKeyHashes": ["QmPPNYiBqpc3gxRG4FrxbBrp3KC8V4pePJxqxgNwkQMpaR"],
            "method": "did:tdw:0.3",
            "scid": "Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6",
        },
        params_update={
            "updateKeys": ["z6MkmTNGEZUFRkfKd5TKooEGfdMqdokphHarKSngiPvvJdGR"],
            "nextKeyHashes": ["QmPPNYiBqpc3gxRG4FrxbBrp3KC8V4pePJxqxgNwkQMpaR"],
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:Qmdr1y71TPEv8kkxKJi5b7H3qTbEak3MXiqmsLrgMVjRj6:domain.example",
        },
        timestamp=datetime(2024, 9, 11, 17, 29, 33, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:33Z",
        version_id="2-QmdmMJ9BevLMnj6ua7CurAN4wa3RDRrCTgzLWGZPyfpfTV",
        version_number=2,
        last_version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
                "created": "2024-09-25T21:26:38Z",
                "proofPurpose": "authentication",
                "proofValue": "zf2DVrNiVhAe6jpqbqzTKNJpZAG5e6gnJTnnCpx3EUVTDabAoYHMK3C4w4BScEystURiH8BNzkAQbQwPECVY2Pzr",
            }
        ],
    )
    verify_proofs(state=current_state, prev_state=prev_state, is_final=False)

    # Bad proof for current state
    current_state.proofs = [
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
            "created": "2024-09-11T17:29:33Z",
            "proofPurpose": "authentication",
            "proofValue": "zbsr8px8V9vLvGMeM9znFJqoRmYeRNLAdn5wJ26XmnBMzSS5bb6Us2JG8TKjtooy3ofdRwaWvY4jb6TCVSyhzapZ",  # this is changed
        }
    ]
    with pytest.raises(ValueError):
        verify_proofs(state=current_state, prev_state=prev_state, is_final=False)
