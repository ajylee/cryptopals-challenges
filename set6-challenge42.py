import re
from hashlib import sha256
import Crypto.Random
from Crypto.Util.asn1 import DerOctetString, DerObject

import number_theory as nt
from my_rsa import (keygen, encrypt, decrypt,
                    long_to_bytes, bytes_to_long)

from pkcs1 import pad, check_and_remove_padding

BLOCK_SIZE = 1024 / 8  # 128 bytes


def sign(privkey, message):
    _hash = sha256(message).digest()
    asn1_hash = DerOctetString(_hash).encode()
    padded = pad(asn1_hash, BLOCK_SIZE)

    return (message, encrypt(privkey, padded))


def _reinstate_initial_0s(plaintext_without_0s):
    # NOTE: The (big-endian) decrypted block has its initial zeros removed.
    return ((BLOCK_SIZE - len(plaintext_without_0s)) * chr(0)
            + plaintext_without_0s)


def verify(pubkey, (message, signature)):
    plaintext = _reinstate_initial_0s(decrypt(pubkey, signature))

    ok_padding, asn1_hash = check_and_remove_padding(
        plaintext, min_padding_string_len=1)

    if not ok_padding:
        return False
    else:
        der = DerObject()
        der.decode(asn1_hash)
        return der.payload == sha256(message).digest()

        
def str_part_cube_root(ss, pad_size):
    rr = 3
    nn = bytes_to_long(ss + chr(0) * pad_size)
    _float_root = nn ** (1./float(rr))
    _guess = long(round(_float_root))
    change = long(round(_guess ** (1. / float(rr))))

    while True:
        _maybe_nn = _guess ** rr

        if '\x00' + long_to_bytes(_maybe_nn)[:-pad_size] == ss:
            return long_to_bytes(_guess)
        else:
            diff = nn - _maybe_nn
            assert diff > 0

            change = max(long(round(diff / float((2 ** rr - 1) * _guess ** 2))),
                         1)

            _guess += change


def break_sig_cube(pubkey, message):
    asn1_hash = DerOctetString(sha256(message).digest()).encode()
    padding = '\x00\x01\xff\x00'
    formatted = padding + asn1_hash 
    pad_size = BLOCK_SIZE - len(formatted)

    assert pad_size > 80, 'need at least pad size 80 to search for a valid cube root'

    sig = _reinstate_initial_0s(
            str_part_cube_root(formatted, pad_size=pad_size))

    return (message, sig)


def test_sign_and_verify():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = Crypto.Random.new().read(100)

    signed = sign(privkey, message)

    assert verify(pubkey, signed)


def test_break_sig():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = 'hi mom'

    signed = break_sig_cube(pubkey, message)

    assert verify(pubkey, signed)


if __name__ == '__main__':
    for ii in xrange(10):
        test_sign_and_verify()

    for ii in xrange(10):
        test_break_sig()
