
import Crypto.Random
import hash_more
import struct


class Keyed_MAC(object):
    def __init__(self, md_hash_algo, key):
        self.md_hash_algo = md_hash_algo
        self.key = key

    def MAC(self, message):
        return bytearray(self.md_hash_algo(self.key + message))

    def authentic(self, MAC_val, message):
        return self.MAC(message) == MAC_val


# Breaking tools
# ---------------

def glue_padding(message_length, length_to_bytes):
    bit_len = message_length * 8
    tail = ''.join(chr(byte) for byte in length_to_bytes(bit_len))

    return (b'\x80'
            + b'\x00' * ((56 - (message_length + 1)) % 64)
            + tail)


def test_glue_padding():
    _length_to_bytes = lambda length: hash_more.big_endian_bytes([length], 8)
    message = Crypto.Random.new().read(621)
    _glue_padding = glue_padding(len(message), _length_to_bytes)

    assert (message + _glue_padding
            == hash_more.md_pad_64(message, _length_to_bytes))
