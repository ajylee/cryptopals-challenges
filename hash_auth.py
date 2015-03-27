
from hash_more import SHA1
import struct


class SHA1_Keyed_MAC(object):
    def __init__(self, key):
        self.key = key

    def MAC(self, message):
        return ''.join(chr(byte) for byte in SHA1(self.key + message))

    def authentic(self, MAC_val, message):
        return self.MAC(message) == MAC_val
