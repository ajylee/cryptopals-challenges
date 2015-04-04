import re
from hashlib import sha256
import Crypto.Random
from Crypto.Util.asn1 import DerOctetString, DerObject

import number_theory as nt
from my_rsa import (keygen, encrypt, decrypt,
                    long_to_bytes, bytes_to_long)

BLOCK_SIZE = 1024 / 8  # 128 bytes


def pad(asn1_hash):
    num_ff = BLOCK_SIZE - len(asn1_hash) - 3
    return chr(0) + chr(1) + num_ff * chr(0xff) + chr(0) + asn1_hash


def check_and_remove_padding(plaintext_signature):
    """If valid padding, removes padding and returns tuple (True, ASN.1 HASH)
    Otherwise returns (False, None)"""

    # NOTE: we cannot directly match the hash content using a regex group
    # because of possible newline chars (\n).
    pattern = chr(0) + chr(1) + chr(0xff) + '+' + chr(0)

    r = re.search(pattern, plaintext_signature)

    if not r:
        return (False, None)
    else:
        pad_len = len(r.group(0))
        asn1_hash = plaintext_signature[pad_len:]
        return (True, asn1_hash)


def sign(privkey, message):
    _hash = sha256(message).digest()
    asn1_hash = DerOctetString(_hash).encode()
    padded = pad(asn1_hash)

    return (message, encrypt(privkey, padded))


def _reinstate_initial_0s(plaintext_without_0s):
    # NOTE: The (big-endian) decrypted block has its initial zeros removed.
    return ((BLOCK_SIZE - len(plaintext_without_0s)) * chr(0)
            + plaintext_without_0s)


def verify(pubkey, (message, signature)):
    plaintext = _reinstate_initial_0s(decrypt(pubkey, signature))

    ok_padding, asn1_hash = check_and_remove_padding(plaintext)

    if not ok_padding:
        return False
    else:
        der = DerObject()
        der.decode(asn1_hash)

        return der.payload == sha256(message).digest()

        
def str_part_cube_root(ss, pad_size=80):
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


def break_sig_cube(message):
    asn1_hash = DerOctetString(sha256(message).digest()).encode()
    padding = '\x00\x01\xff\x00'
    formatted = padding + asn1_hash 

    sig = _reinstate_initial_0s(
            str_part_cube_root(formatted))

    return (message, sig)


def test_sign_and_verify():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = Crypto.Random.new().read(100)

    signed = sign(privkey, message)

    assert verify(pubkey, signed)


def test_break_sig():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = 'hi mom'

    signed = break_sig_cube(message)

    assert verify(pubkey, signed)


if __name__ == '__main__':
    for ii in xrange(20):
        test_sign_and_verify()
    test_break_sig()
