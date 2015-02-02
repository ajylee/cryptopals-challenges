
import toolz as tz
import base64
import os.path as osp

from Crypto.Cipher import AES

import gen
from block_crypto import xor_cipher, strxor, pad
from set1_challenge6 import chunks


class CBC(object):
    @staticmethod
    def new(key, iv):
        return CBC(key, iv)

    def __init__(self, key, iv):
        self._ecb_cipher = AES.new(key, AES.MODE_ECB)
        self.block_size = len(key)
        self._iv = iv
        self._cipher_iv = self._ecb_cipher.encrypt(iv)

    def encrypt(self, strn):
        cc = self._ecb_cipher
        padded = pad(strn, block_size=self.block_size)
        _blocks = chunks(padded, size=self.block_size)
        encrypted = [None] * len(_blocks)

        for ii, _block_ii in enumerate(_blocks):
            prev_block = (self._cipher_iv if ii == 0
                          else encrypted[ii-1])
            encrypted[ii] = cc.encrypt(strxor(_block_ii, prev_block))

        return ''.join(encrypted)

    def decrypt(self, strn):
        cc = self._ecb_cipher
        _blocks = chunks(strn, size=self.block_size)
        decrypted = [None] * len(_blocks)

        for ii, _block_ii in enumerate(_blocks):
            prev_block = (self._cipher_iv if ii == 0
                          else _blocks[ii-1])
            decrypted[ii] = strxor(cc.decrypt(_block_ii), prev_block)

        return ''.join(decrypted)


def test_cipher():
    strn = 'hello ' * 20
    key = b'YELLOW SUBMARINE'
    iv = chr(0) * len(key)

    c = CBC.new(key, iv)
    enc = c.encrypt(strn)
    print repr(enc)
    assert c.decrypt(enc).startswith(strn)


def solve():
    with open(osp.join(gen.datadir, '10.txt')) as f:
        strn = base64.b64decode(f.read())

    key = b'YELLOW SUBMARINE'
    iv = chr(0) * len(key)

    for line in CBC.new(key, iv).decrypt(strn).split('\n'):
        print repr(line)


if __name__ == '__main__':
    test_cipher()
    solve()
