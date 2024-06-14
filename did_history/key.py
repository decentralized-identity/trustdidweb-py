from typing import ClassVar, Tuple

from multiformats import multibase, multicodec


class MultiKey(str):
    BASE: ClassVar[str] = "base58btc"

    @classmethod
    def from_public_key(cls, codec: str, pk: bytes) -> "MultiKey":
        pk_enc = multibase.encode(multicodec.wrap(codec, pk), MultiKey.BASE)
        return MultiKey(pk_enc)

    def decode(self) -> Tuple[str, bytes]:
        try:
            base, pk_mc = multibase.decode_raw(self)
            codec, pk_b = multicodec.unwrap(pk_mc)
        except KeyError as e:
            raise ValueError("Error decoding did:key") from e
        if base.name != MultiKey.BASE:
            raise ValueError("Unexpected multibase encoding for multikey")
        return (codec, pk_b)
