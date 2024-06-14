import base64

import jsoncanon


def format_hash(digest: bytes) -> str:
    return base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def normalize_log_line(line: list) -> bytes:
    return jsoncanon.canonicalize(line)
