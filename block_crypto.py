import itertools
import random
from Crypto.Cipher import AES


def strxor(s1, s2):
    return ''.join(chr(ord(_c1) ^ ord(_c2))
               for _c1, _c2 in itertools.izip(s1, s2))


def pad(strn, block_size, pad_str=chr(4)):
    assert len(pad_str) == 1
    return strn + pad_str * (-len(strn) % block_size)


def xor_cipher(data, key):
    _salt = len(data) // len(key) * key + key[:len(data) % len(key)]
    return strxor(data, _salt)


def random_str(length=16):
    return ''.join(chr(random.randint(0, 255))
               for ii in xrange(length))


def chunks(ss, size, num_chunks=None):
    if num_chunks != None:
        assert len(ss) >= size * num_chunks
    else:
        num_chunks = len(ss) // size

    def nth_slice(nn):
        start = size * nn
        end = start + size
        return slice(start, end)

    return [ss[nth_slice(ii)]
        for ii in xrange(num_chunks)]


class CBC(object):
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


# Retry stochastic fn
# --------------------

class GaveUp(Exception):
    pass


def try_repeatedly(thunk, max_tries):
    tries = 0

    while tries < max_tries:
        maybe = thunk()
        if maybe:
            return maybe
        else:
            tries += 1

    raise GaveUp, 'not found'


# Strip padding
# --------------

INVALID_CHARS = ''.join(
    map(chr, set(xrange(32)) - {9,    # \t
                                10,   # \n
                                13,   # \r
                                4,    # pad
                            }))


class InvalidPadding(Exception):
    pass


def strip_PKCS7_padding(plaintext):
    if any(_invalid in plaintext for _invalid in INVALID_CHARS):
        raise InvalidPadding
    else:
        return plaintext.rstrip(chr(4))
