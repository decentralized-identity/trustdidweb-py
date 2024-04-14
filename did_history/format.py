import base64
import json

from typing import Union

import jsoncanon

SCID_PLACEHOLDER = "{SCID}"


def format_hash(digest: bytes) -> str:
    return base64.b32encode(digest).decode("ascii").lower().rstrip("=")


def normalize_log_line(line: list) -> bytes:
    return jsoncanon.canonicalize(line)


def normalize_genesis(document: Union[dict, str], check_scid: str = None) -> bytes:
    if isinstance(document, str):
        document = json.loads(document)
    norm = jsoncanon.canonicalize(document).decode("ascii")
    if check_scid is not None:
        if check_scid not in norm:
            raise ValueError("SCID not found in document")
        norm = norm.replace(check_scid, SCID_PLACEHOLDER)
    elif SCID_PLACEHOLDER not in norm:
        raise ValueError("SCID placeholder not found in document")
    return norm.encode("utf-8")
