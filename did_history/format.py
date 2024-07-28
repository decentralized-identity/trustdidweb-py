import base58
import jsoncanon

from multiformats import multihash


def format_hash(digest: bytes) -> str:
    return base58.b58encode(multihash.wrap(digest, "sha2-256")).decode("ascii")


def normalize_log_line(line: list) -> bytes:
    return jsoncanon.canonicalize(line)
