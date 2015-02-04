
from block_crypto import strip_PKCS7_padding, InvalidPadding
import nose


def test_strip_pkcs7_padding():
    assert strip_PKCS7_padding("ICE ICE BABY\x04\x04\x04\x04") == (
        "ICE ICE BABY")

    nose.tools.assert_raises(
        InvalidPadding,
        strip_PKCS7_padding,
        "ICE ICE BABY\x05\x05\x05\x05"
        )

    nose.tools.assert_raises(
        InvalidPadding,
        strip_PKCS7_padding,
        "ICE ICE BABY\x01\x02\x03\x04"
        )
