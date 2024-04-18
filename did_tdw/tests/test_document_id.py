import pytest

from did_tdw.proof import check_document_id_format


TEST_SCID = "0000000000000000000000000000"

VALID_DID = [
    "did:tdw:0000000000000000000000000000.mydomain.com",
    "did:tdw:mydomain.com:0000000000000000000000000000",
    "did:tdw:mydomain.com:path:0000000000000000000000000000",
    "did:tdw:mydomain.com:0000000000000000000000000000:path:path",
]
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


@pytest.mark.parametrize("did", VALID_DID)
def test_valid_document_id(did: str):
    check_document_id_format(did, "0000000000000000000000000000")


@pytest.mark.parametrize("did", INVALID_DID)
def test_invalid_document_id(did: str):
    with pytest.raises(ValueError):
        check_document_id_format(did, "0000000000000000000000000000")
