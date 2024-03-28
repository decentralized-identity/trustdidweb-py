import re

from urllib.parse import parse_qs


class DIDUrl:
    PATTERN = re.compile(
        "^did:([a-z0-9]+):((?:[a-zA-Z0-9%_\.\-]*:)*[a-zA-Z0-9%_\.\-]+)$"
    )

    method: str
    identifier: str
    path: str
    query: str
    fragment: str

    def __init__(
        self,
        method: str,
        identifier: str,
        path: str = None,
        query: str = None,
        fragment: str = None,
    ):
        self.method = method
        self.identifier = identifier
        self.path = path
        self.query = query
        self.fragment = fragment

    @property
    def root(self) -> "DIDUrl":
        return DIDUrl(method=self.method, identifier=self.identifier)

    @classmethod
    def decode(cls, url: str) -> "DIDUrl":
        path = None
        query = None
        fragment = None
        if "#" in url:
            url, fragment = url.split("#", 1)
        if "?" in url:
            url, query = url.split("?", 1)
        # FIXME check fragment, query, path only contain pchars
        # [a-zA-Z0-9\-\._~%:@!\$&'()*+,;=]*
        if "/" in url:
            url, path = url.split("/", 1)
        parts = cls.PATTERN.match(url)
        if not parts:
            raise ValueError("Invalid DID URL")
        return DIDUrl(parts[1], parts[2], path, query, fragment)

    @property
    def did(self) -> str:
        return f"did:{self.method}:{self.identifier}"

    @property
    def query_dict(self) -> dict:
        if self.query:
            return {k: v[-1] for k, v in parse_qs(self.query)}
        return {}
