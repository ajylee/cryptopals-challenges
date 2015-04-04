import re
from hashlib import sha256
import Crypto.Random
from Crypto.Util.asn1 import DerOctetString, DerObject
from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_rsa import keygen, encrypt, decrypt

BLOCK_SIZE = 1024 / 8  # 128 bytes


def pad(asn1_hash):
    num_ff = BLOCK_SIZE - len(asn1_hash) - 3
    return chr(0) + chr(1) + num_ff * chr(0xff) + chr(0) + asn1_hash


def check_and_remove_padding(plaintext_signature):
    """If valid padding, removes padding and returns tuple (True, ASN.1 HASH)
    Otherwise returns (False, None)"""

    pattern = chr(0) + chr(1) + chr(0xff) + '+' + chr(0) + '(.*)'

    r = re.search(pattern, plaintext_signature)

    if not r:
        return (False, None)
    else:
        return (True, r.group(1))


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
        return der.payload == _hash = sha256(message).digest()


def break_sig_cube(message):
    asn1_hash = DerOctetString(sha256(message).digest()).encode()
    padding = '\x00\x01\xff\x00'
    formatted = padding + asn1_hash + (BLOCK_SIZE - len(padding)) * chr(0)

    return _reinstate_initial_0s(
        long_to_bytes(
            nt.long_root(
                bytes_to_long(formatted), 3)))


def test_sign_and_verify():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = Crypto.Random.new().read(100)

    signed = sign(privkey, message)

    assert verify(pubkey, signed)
    assert verify(pubkey, signed)


def test_break_sig():
    pubkey, privkey = keygen(BLOCK_SIZE)

    message = 'hi mom'

    signed = sign(privkey, message)

    verify(pubkey, signed)


if __name__ == '__main__':
    test_sign_and_verify()
