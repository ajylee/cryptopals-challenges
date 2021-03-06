
import struct
import Crypto.Random
from Crypto.Util.strxor import strxor
from block_crypto import chunks

import hash_more
import hash_auth


def gen_MAC(md_hash_algo, hash_to_state, orig_MAC, total_byte_len, added_message):
    return bytearray(md_hash_algo(added_message,
                                  fake_byte_len=total_byte_len,
                                  state=hash_to_state(orig_MAC)))

def gen_MAC_and_message_candidates(
        md_hash_algo, hash_to_state, length_to_bytes,
        guessed_key_len, orig_MAC, orig_message, added_message):

    new_message_candidate = (orig_message
                             + hash_auth.glue_padding(
                                 guessed_key_len + len(orig_message),
                                 length_to_bytes)
                             + added_message)

    total_byte_len = guessed_key_len + len(new_message_candidate)

    new_MAC_candidate = gen_MAC(md_hash_algo, hash_to_state,
                                orig_MAC, total_byte_len, added_message)

    return new_MAC_candidate, new_message_candidate


def gen_MAC_and_message(md_hash_algo, hash_to_state, length_to_bytes,
                        auth, orig_MAC, orig_message, added_message):
    for guessed_key_len in xrange(100):
        new_MAC_candidate, new_message_candidate =(
            gen_MAC_and_message_candidates(
                md_hash_algo, hash_to_state, length_to_bytes,
                guessed_key_len, orig_MAC, orig_message, added_message))

        if auth.authentic(new_MAC_candidate, new_message_candidate):
            return new_MAC_candidate, new_message_candidate
    else:
        raise ValueError, "failed generate valid message"


def break_keyed_MAC(md_hash_algo, hash_to_state, length_to_bytes):

    random_io = Crypto.Random.new()

    key = random_io.read(16)
    message = ("comment1=cooking%20MCs;"
               "userdata=foo;"
               "comment2=%20like%20a%20pound%20of%20bacon" )

    auth = hash_auth.Keyed_MAC(md_hash_algo, key)
    real_MAC = auth.MAC(message)

    assert auth.authentic(real_MAC, message)

    added_message = ";admin=true"

    fake_MAC, tampered_message = gen_MAC_and_message(
        md_hash_algo, hash_to_state, length_to_bytes,
        auth, real_MAC, message, added_message)

    assert tampered_message.endswith(added_message)
    assert auth.authentic(fake_MAC, tampered_message)


def test_break_SHA1_keyed_MAC():
    def _hash_to_state(hash_str):
        return list(hash_more.big_endian_words(bytearray(hash_str), 4))

    break_keyed_MAC(hash_more.SHA1,
                    _hash_to_state,
                    lambda length: hash_more.big_endian_bytes([length], 8))


def test_break_MD4_keyed_MAC():
    def _hash_to_state(hash_str):
        return list(hash_more.little_endian_words(bytearray(hash_str), 4))

    break_keyed_MAC(hash_more.MD4,
                    _hash_to_state,
                    lambda length: hash_more.little_endian_bytes([length], 8))


if __name__ == '__main__':
    test_break_SHA1_keyed_MAC()
    test_break_MD4_keyed_MAC()
