"""Domain and path handling for did:tdw identifiers."""

import urllib
from dataclasses import dataclass, field
from typing import Optional

from .core.did_url import SCID_PLACEHOLDER


@dataclass
class DomainPath:
    """Domain and path (and port) compatible with a did:tdw identifier."""

    scid: str
    domain: str
    port: Optional[int] = None
    path: list[str] = field(default_factory=list)

    @classmethod
    def parse_normalized(cls, path: str) -> "DomainPath":
        """Parse a domain and path in normalized format (domain:port/path)."""
        id_parts = path.split("/")
        host = urllib.parse.unquote(id_parts[0])
        if ":" in host:
            host, port_str = host.split(":", 1)
            if not port_str.isdecimal():
                raise ValueError("Invalid port specification")
            port = int(port_str)
        else:
            port = None
        path = id_parts[1:]
        if path and not path[-1]:
            path.pop()
        ret = DomainPath(scid=SCID_PLACEHOLDER, domain=host, port=port, path=path)
        ret.validate()
        return ret

    @classmethod
    def parse_identifier(cls, doc_id: str) -> "DomainPath":
        """Parse a domain and path in identifier format (scid:domain%3Aport:path)."""
        scid, *id_parts = doc_id.split(":")
        if not id_parts:
            raise ValueError("Invalid identifier")
        host = urllib.parse.unquote(id_parts[0])
        if ":" in host:
            host, port_str = host.split(":", 1)
            if not port_str.isdecimal():
                raise ValueError("Invalid port specification")
            port = int(port_str)
        else:
            port = None
        ret = DomainPath(scid=scid, domain=host, port=port, path=id_parts[1:])
        ret.validate()
        return ret

    @property
    def identifier(self) -> str:
        """Convert into identifier format."""
        domain = self.domain
        if self.port:
            domain += f"%3A{self.port}"
        return ":".join((self.scid, domain, *self.path))

    @property
    def domain_port(self):
        """Access the combined domain name and port in URL format."""
        domain = self.domain
        if self.port:
            domain += f":{self.port}"
        return domain

    def __str__(self) -> str:
        """Convert into normalized format."""
        return "/".join((self.domain_port, *self.path))

    def validate(self):
        """Validate the domain and path."""
        domain = self.domain.split(".")
        if len(domain) < 2 or not all(len(s) >= 2 and s[:1].isalpha() for s in domain):
            raise ValueError("Invalid domain name in method-specific ID")
        if self.path:
            for p in self.path:
                if not p:
                    raise ValueError("Invalid path in method-specific ID")
