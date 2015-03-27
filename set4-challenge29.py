
import struct
import Crypto.Random
from Crypto.Util.strxor import strxor
from block_crypto import chunks
from hash_more import (SHA1, sha1_compress, make_md_hash_64, big_endian_bytes,
                       md_pad_64, big_endian_words, little_endian_words)
import hash_auth

_length_to_bytes = lambda length: big_endian_bytes([length], 8)


def glue_padding(message_length):
    bit_len = message_length * 8
    tail = ''.join(chr(byte) for byte in _length_to_bytes(bit_len))

    return (b'\x80'
            + b'\x00' * ((56 - (message_length + 1)) % 64)
            + tail)


def gen_MAC(orig_MAC, added_message):
    state = list(big_endian_words((ord(c) for c in orig_MAC), 4))
    return SHA1(added_message, state=state)


def gen_message(auth, fake_MAC, orig_message, added_message):
    for guessed_key_len in xrange(100):
        new_message_candidate = (orig_message
                                 + glue_padding(guessed_key_len
                                                + len(orig_message))
                                 + added_message)
        if auth.authentic(fake_MAC, new_message_candidate):
            return new_message_candidate
    else:
        raise ValueError, "failed generate valid message"


def test_glue_padding():
    message = Crypto.Random.new().read(20)
    _glue_padding = glue_padding(len(message))
    assert (message + _glue_padding
            == md_pad_64(message, _length_to_bytes))


def test_break_SHA1_keyed_MAC():
    random_io = Crypto.Random.new()

    key = random_io.read(16)
    message = ("comment1=cooking%20MCs;"
               "userdata=foo;"
               "comment2=%20like%20a%20pound%20of%20bacon" )

    auth = hash_auth.SHA1_Keyed_MAC(key)
    real_MAC = auth.MAC(message)

    assert auth.authentic(real_MAC, message)

    added_message = ";admin=true" 

    fake_MAC = gen_MAC(real_MAC, added_message)


    assert auth.authentic(fake_MAC, (message
                                     + glue_padding(len(key) + len(message))
                                     + added_message))

    
    tampered_message = gen_message(auth, fake_MAC, message,
                                   added_message)

    assert tampered_message == (message
                                + glue_padding(len(key) + len(message))
                                + added_message)

    assert auth.authentic(fake_MAC, tampered_message)
    print tampered_message


if __name__ == '__main__':
    test_glue_padding()
    test_break_SHA1_keyed_MAC()
