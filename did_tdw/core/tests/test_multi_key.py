import pytest

from did_tdw.core.multi_key import MultiKey


def test_multi_key():
    pk = b"\xaby\xbaw\xfaa\x9f\xf2\xc9r\xfd\x9a\xeb\x830.\xda\x8e$U%_\xfe\x1a\x13\xf0\x9b\x1b+\xdc\x1e_"
    codec = "ed25519-pub"
    multi_key = MultiKey.from_public_key(codec, pk)
    assert isinstance(multi_key, MultiKey)
    (decoded_codec, decoded_pk_b) = multi_key.decode()
    assert decoded_codec.name == codec
    assert decoded_pk_b == pk

    # Public key is not bytes
    pk_bad = "\xaby\xbaw\xfaa\x9f\xf2\xc9r\xfd\x9a\xeb\x830.\xda\x8e$U%_\xfe\x1a\x13\xf0\x9b\x1b+\xdc\x1e_"
    with pytest.raises(TypeError):
        MultiKey.from_public_key(codec, pk_bad)

    # Invalid codec
    codec_bad = "edd225"
    with pytest.raises(ValueError):
        MultiKey.from_public_key(codec_bad, pk)
