"""DID URL format handling."""

import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import parse_qs

SCID_PLACEHOLDER = "{SCID}"


@dataclass
class DIDUrl:
    """A DID URL as defined by Decentralized Identifiers 1.0."""

    PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^did:([a-z0-9]+):((?:[a-zA-Z0-9%_\.\-]*:)*[a-zA-Z0-9%_\.\-]+)$"
    )

    method: str
    identifier: str
    path: str = None
    query: str = None
    fragment: str = None

    @property
    def root(self) -> "DIDUrl":
        """Access this DID URL without any path, fragment, or query parameters."""
        return DIDUrl(method=self.method, identifier=self.identifier)

    @classmethod
    def decode(cls, url: str) -> "DIDUrl":
        """Decode a string as a DID URL.

        Raises:
            ValueError: on invalid inputs

        """
        path = None
        query = None
        fragment = None
        if (pos := url.find("#")) >= 0:
            fragment = url[pos:]
            url = url[:pos]
        if (pos := url.find("?")) >= 0:
            query = url[pos:]
            url = url[:pos]
        # FIXME check fragment, query, path only contain pchars
        # [a-zA-Z0-9\-\._~%:@!\$&'()*+,;=]*
        if (pos := url.find("/")) >= 0:
            path = url[pos:]
            url = url[:pos]
        parts = cls.PATTERN.match(url)
        if not parts:
            raise ValueError("Invalid DID URL")
        return DIDUrl(
            method=parts[1],
            identifier=parts[2],
            path=path,
            query=query,
            fragment=fragment,
        )

    @property
    def did(self) -> str:
        """Access the root DID identifier for this DID URL."""
        return f"did:{self.method}:{self.identifier}"

    @property
    def query_dict(self) -> dict:
        """Extract a parameter dictionary for this DID URL."""
        if self.query:
            return {k: v[-1] for k, v in parse_qs(self.query)}
        return {}
