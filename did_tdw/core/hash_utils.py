"""Hashing utilities and metadata."""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import TypeAlias

import base58
from multiformats import multihash

HashFn: TypeAlias = Callable[[bytes], bytes]


DEFAULT_HASH = "sha2-256"
HASH_FN_MAP: dict[str, HashFn] = {
    "sha2-256": lambda b: sha256(b).digest(),
    # "sha3-256": lambda b: sha3_256(b).digest(),
}


@dataclass
class HashInfo:
    """Descriptor for a hash method."""

    hash: HashFn
    name: str

    @classmethod
    def from_name(cls, hash_name: str) -> "HashInfo":
        """Resolve a hash descriptor from its unique identifier."""
        if hash_name in HASH_FN_MAP:
            return HashInfo(hash=HASH_FN_MAP[hash_name], name=hash_name)
        raise ValueError(f"Unsupported hash function: {hash_name}")

    @classmethod
    def identify_hash(cls, mhash: str) -> "HashInfo":
        """Try to resolve a hash descriptor from a multihash-encoded hash."""
        try:
            codec = multihash.from_digest(base58.b58decode(mhash))
        except KeyError as err:
            raise KeyError("Unrecognized hash function") from err
        return HashInfo.from_name(codec.name)

    def format_digest(self, digest: bytes) -> str:
        """Format a hash digest in the multihash encoding."""
        return base58.b58encode(multihash.wrap(digest, self.name)).decode("ascii")

    def formatted_hash(self, data: bytes) -> str:
        """Hash a value and return the multihash encoding."""
        return self.format_digest(self.hash(data))
