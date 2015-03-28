
import struct
import Crypto.Random
from Crypto.Util.strxor import strxor
from block_crypto import chunks
from hash_more import (SHA1, sha1_compress, make_md_hash_64, big_endian_bytes,
                       md_pad_64, big_endian_words, little_endian_words)
import hash_auth

_length_to_bytes = lambda length: big_endian_bytes([length], 8)


# Debug tools
# ------------

def check_hash(message, state):
    """tool for debugging"""
    for i in range(0, len(message), 64):
        state = sha1_compress(message[i:i+64], state)
    return _state_to_hash(state)


def _state_to_hash(state):
    _bytes = big_endian_bytes(state, 4)
    return ''.join(chr(byte) for byte in _bytes)


def _hash_to_state(sha1_hash_str):
    return list(big_endian_words(bytearray(sha1_hash_str), 4))


def _add_glue_padding(message):
     return message + glue_padding(len(message))


# Code proper
# ------------

def glue_padding(message_length):
    bit_len = message_length * 8
    tail = ''.join(chr(byte) for byte in _length_to_bytes(bit_len))

    return (b'\x80'
            + b'\x00' * ((56 - (message_length + 1)) % 64)
            + tail)


def gen_MAC(orig_MAC, total_byte_len, added_message):
    return bytearray(SHA1(added_message,
                          fake_byte_len=total_byte_len,
                          state=_hash_to_state(orig_MAC)))


def gen_MAC_and_message_candidates(
        guessed_key_len, orig_MAC, orig_message, added_message):

    new_message_candidate = (orig_message
                             + glue_padding(guessed_key_len + len(orig_message))
                             + added_message)

    total_byte_len = guessed_key_len + len(new_message_candidate)

    new_MAC_candidate = gen_MAC(orig_MAC, total_byte_len, added_message)

    return new_MAC_candidate, new_message_candidate


def gen_MAC_and_message(auth, orig_MAC, orig_message, added_message):
    for guessed_key_len in xrange(100):
        new_MAC_candidate, new_message_candidate =(
            gen_MAC_and_message_candidates(
                guessed_key_len, orig_MAC, orig_message, added_message))

        if auth.authentic(new_MAC_candidate, new_message_candidate):
            return new_MAC_candidate, new_message_candidate
    else:
        raise ValueError, "failed generate valid message"


def test_glue_padding():
    message = Crypto.Random.new().read(621)
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

    fake_MAC, tampered_message = gen_MAC_and_message(
        auth, real_MAC, message, added_message)

    assert tampered_message.endswith(added_message)
    assert auth.authentic(fake_MAC, tampered_message)


if __name__ == '__main__':
    test_glue_padding()
    test_break_SHA1_keyed_MAC()
