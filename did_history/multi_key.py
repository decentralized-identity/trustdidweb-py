"""MultiKey format handling."""

from typing import ClassVar

from multiformats import multibase, multicodec


class MultiKey(str):
    """MultiKey string representation."""

    BASE: ClassVar[str] = "base58btc"

    @classmethod
    def from_public_key(cls, codec: str, pk: bytes) -> "MultiKey":
        """Encode public key bytes as a MultiKey."""
        try:
            pk_wrap = multicodec.wrap(codec, pk)
        except KeyError:
            raise ValueError("Unsupported codec: {codec}") from None
        try:
            pk_enc = multibase.encode(pk_wrap, MultiKey.BASE)
        except (KeyError, ValueError):
            raise ValueError(f"Unsupported multibase encoding: {MultiKey.BASE}") from None
        return MultiKey(pk_enc)

    def decode(self) -> tuple[str, bytes]:
        """Decode this MultiKey into a codec identifier and public key."""
        try:
            base, pk_mc = multibase.decode_raw(self)
            codec, pk_b = multicodec.unwrap(pk_mc)
        except KeyError as e:
            raise ValueError("Error decoding did:key") from e
        if base.name != MultiKey.BASE:
            raise ValueError("Unexpected multibase encoding for multikey")
        return (codec, pk_b)
