from dataclasses import dataclass
from hashlib import sha256, sha3_256
from typing import Callable, TypeAlias

import base58
import jsoncanon

from multiformats import multihash

HashFn: TypeAlias = Callable[[bytes], bytes]


HASH_FN_MAP: dict[str, HashFn] = {
    "sha2-256": lambda b: sha256(b).digest(),
    "sha3-256": lambda b: sha3_256(b).digest(),
}


@dataclass
class HashInfo:
    hash: HashFn
    name: str

    def from_name(hash_name: str) -> "HashInfo":
        if hash_name in HASH_FN_MAP:
            return HashInfo(hash=HASH_FN_MAP[hash_name], name=hash_name)
        raise ValueError(f"Unsupported hash function: {hash_name}")


def format_hash(digest: bytes) -> str:
    return base58.b58encode(multihash.wrap(digest, "sha2-256")).decode("ascii")


def identify_hash(mhash: str) -> HashInfo:
    codec = multihash.from_digest(base58.b58decode(mhash))
    return HashInfo.from_name(codec.name)


def normalize_log_line(line: list) -> bytes:
    return jsoncanon.canonicalize(line)
