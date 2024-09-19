from copy import deepcopy
from unittest import mock

import pytest

from did_history.resolver import (
    DereferencingResult,
    ResolutionResult,
    dereference_fragment,
    normalize_services,
    reference_map,
    resolve_history,
)

mock_history_iterator = mock.AsyncMock()
mock_history_iterator.__aiter__.return_value = iter(
    [
        '["1-QmToCZBHUFeYhChZrn65Ww5UhdzaBriYaCLcUmBh1DC52h", "2024-09-09T18:57:28Z", {"updateKeys": ["z6Mkk9dFo3jzVKFsNACaaGqZmgBBxktGKuid3QXWsrJFkq4c"], "method": "did:tdw:0.3", "scid": "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4"}, {"value": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000"}}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mkk9dFo3jzVKFsNACaaGqZmgBBxktGKuid3QXWsrJFkq4c#z6Mkk9dFo3jzVKFsNACaaGqZmgBBxktGKuid3QXWsrJFkq4c", "created": "2024-09-09T18:57:28Z", "proofPurpose": "authentication", "challenge": "1-QmToCZBHUFeYhChZrn65Ww5UhdzaBriYaCLcUmBh1DC52h", "proofValue": "z2UrBUD3xGUUnhCcH51sgRsFDtZjsx4X2xTuToRAfyrZ2ShdUGeeLxrYEHWBBCKB6HmU1hsK57Qi8CP9ND85Z5PK4"}]]',
        '["2-QmUuhGnfMoW8P5JCMWUJi4Ns3WkHsStj2ZEhzpMU7PV8QK", "2024-09-09T18:57:29Z", {}, {"patch": [{"op": "add", "path": "/authentication", "value": ["did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"]}, {"op": "add", "path": "/service", "value": [{"id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain", "type": "LinkedDomains", "serviceEndpoint": "https://example.com%3A5000"}, {"id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois", "type": "LinkedVerifiablePresentation", "serviceEndpoint": "https://example.com%3A5000/.well-known/whois.vc"}]}, {"op": "add", "path": "/verificationMethod", "value": [{"id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs", "controller": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000", "type": "Multikey", "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"}]}, {"op": "add", "path": "/assertionMethod", "value": ["did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"]}, {"op": "add", "path": "/@context/1", "value": "https://w3id.org/security/multikey/v1"}, {"op": "add", "path": "/@context/2", "value": "https://identity.foundation/.well-known/did-configuration/v1"}, {"op": "add", "path": "/@context/3", "value": "https://identity.foundation/linked-vp/contexts/v1"}]}, [{"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "verificationMethod": "did:key:z6Mkk9dFo3jzVKFsNACaaGqZmgBBxktGKuid3QXWsrJFkq4c#z6Mkk9dFo3jzVKFsNACaaGqZmgBBxktGKuid3QXWsrJFkq4c", "created": "2024-09-09T18:57:29Z", "proofPurpose": "authentication", "challenge": "2-QmUuhGnfMoW8P5JCMWUJi4Ns3WkHsStj2ZEhzpMU7PV8QK", "proofValue": "z2wPpginNzhQgb2ztGjHMfEba7tcMkuAkGYzV8qpGoQaVmtno4Z8AmSZhMP4ry9dnN7LMS6kWQcR23yx3yHL1eafY"}]]',
    ]
)

mock_document = {
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


async def test_resolve_history():
    result = await resolve_history(
        "QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4", mock_history_iterator
    )
    assert isinstance(result, ResolutionResult)


def test_reference_map():
    result = reference_map(mock_document)
    assert isinstance(result, dict)

    # Use dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }
    reference_map(services_in_dict_document)

    # id isn't a string
    bad_id_document = deepcopy(mock_document)
    bad_id_document["id"] = 123
    with pytest.raises(ValueError):
        reference_map(bad_id_document)


def test_normalize_services():
    result = normalize_services(mock_document)
    assert isinstance(result, list)

    # Service isn't a dict
    bad_service_document = deepcopy(mock_document)
    bad_service_document["service"] = [
        '{"id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain","type": "LinkedDomains","serviceEndpoint": "https://example.com%3A5000"}'
    ]

    with pytest.raises(ValueError):
        normalize_services(bad_service_document)

    # Service doesn't contain # symbol
    no_hash_symbol_document = deepcopy(mock_document)
    no_hash_symbol_document["service"] = [
        {
            "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com%3A5000",
        },
        {
            "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com%3A5000/.well-known/whois.vc",
        },
    ]

    with pytest.raises(ValueError):
        normalize_services(no_hash_symbol_document)

    # Services are in a dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }

    normalize_services(services_in_dict_document)


def test_dereference_fragment():
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )
    assert isinstance(result, DereferencingResult)
    result = dereference_fragment(mock_document, "#domain")
    assert isinstance(result, DereferencingResult)

    # This ref doesn't exist
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAz"
    )
    assert isinstance(result, DereferencingResult)
    assert result.dereferencing_metadata.get("error") is not None
