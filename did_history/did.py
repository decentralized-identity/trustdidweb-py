import re

from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import parse_qs


@dataclass
class DIDUrl:
    PATTERN: ClassVar[re.Pattern] = re.compile(
        "^did:([a-z0-9]+):((?:[a-zA-Z0-9%_\.\-]*:)*[a-zA-Z0-9%_\.\-]+)$"
    )

    method: str
    identifier: str
    path: str = None
    query: str = None
    fragment: str = None

    @property
    def root(self) -> "DIDUrl":
        return DIDUrl(method=self.method, identifier=self.identifier)

    @classmethod
    def decode(cls, url: str) -> "DIDUrl":
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
        return f"did:{self.method}:{self.identifier}"

    @property
    def query_dict(self) -> dict:
        if self.query:
            return {k: v[-1] for k, v in parse_qs(self.query)}
        return {}
