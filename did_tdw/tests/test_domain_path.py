import pytest

from did_tdw.domain_path import DomainPath


def test_parse_normalized_domain_path():
    checks = {
        "mydomain.com": "{SCID}:mydomain.com",
        "mydomain.com:80/": "{SCID}:mydomain.com%3A80",
        "domain.example/path/path": "{SCID}:domain.example:path:path",
        "domain.example/path/path/": "{SCID}:domain.example:path:path",
    }

    for check, expect in checks.items():
        d = DomainPath.parse_normalized(check)
        assert d.identifier == expect


def test_parse_normalized_invalid_domain_path():
    checks = [
        "mydomain.",
        ".domain",
        "domain..com",
        "domain.com:port",
        "domain.example//",
    ]

    for check in checks:
        with pytest.raises(ValueError):
            _ = DomainPath.parse_normalized(check)
