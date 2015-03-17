import math
import toolz as tz
import itertools
import random
from Crypto.Cipher import AES
from bin_more import chrs as int_to_chrs
import logging

logger = logging.getLogger(__name__)


def strxor(s1, s2):
    return ''.join(chr(ord(_c1) ^ ord(_c2))
               for _c1, _c2 in itertools.izip(s1, s2))


def pad(strn, block_size):
    if len(strn) % block_size != 0:
        pad_len = -len(strn) % block_size
    else:
        pad_len = block_size

    return strn + chr(pad_len) * pad_len


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
    def __init__(self, key, iv, encipher_iv=False):
        self._ecb_cipher = AES.new(key, AES.MODE_ECB)
        self.block_size = len(key)
        self._iv = iv

        if encipher_iv:
            # enciphering the iv hinders PKCS7 oracle
            self._cipher_iv = self._ecb_cipher.encrypt(iv)
        else:
            self._cipher_iv = self._iv

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


class RandCBC(object):
    def __init__(self, block_size, encipher_iv=False):
        self.block_size = block_size
        self.key = random_str(self.block_size)
        self.encipher_iv = encipher_iv

    def encrypt(self, data):
        iv = random_str(self.block_size)
        return iv + CBC(key=self.key, iv=iv, encipher_iv=self.encipher_iv).encrypt(data)

    def decrypt(self, iv_ciphertext):
        iv = iv_ciphertext[:self.block_size]
        ciphertext = iv_ciphertext[self.block_size:]
        return CBC(key=self.key, iv=iv, encipher_iv=self.encipher_iv).decrypt(ciphertext)


class CTR(object):
    def __init__(self, key, nonce):
        self.nonce = nonce

        self._ecb_cipher = AES.new(key, AES.MODE_ECB)
        self.block_size = len(key)
        assert self.block_size % 2 == 0

    def keystream_block(self, count):
        half_width = self.block_size // 2

        def _pad0(ss):
            assert len(ss) <= half_width
            return ss + (half_width - len(ss)) * chr(0)

        plain = _pad0(int_to_chrs(self.nonce)) + _pad0(int_to_chrs(count))
        logger.debug('raw xor_key {}'.format(repr(plain)))
        return self._ecb_cipher.encrypt(plain)

    def transcrypt_block(self, count, block):
        xorkey = self.keystream_block(count)[:len(block)]
        return strxor(xorkey, block)

    def encrypt(self, data):
        def blocks():
            nblocks = int(math.ceil(float(len(data)) / float(self.block_size)))
            for count in xrange(nblocks):
                block = data[count * self.block_size: (count + 1) * self.block_size]
                logger.debug('{} {}'.format(count, repr(block)))
                yield (count, block)

        return ''.join(self.transcrypt_block(count, text_block)
                       for count, text_block in blocks())

    def decrypt(self, data):
        ## encryption / decryption is symmetric
        return self.encrypt(data)


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

class InvalidPadding(Exception):
    pass


def valid_PKCS7_padding(plaintext):
    padding_char = plaintext[-1]
    pad_len = ord(padding_char)
    return (pad_len > 0) and plaintext.endswith(padding_char * pad_len)


def strip_PKCS7_padding(plaintext):
    if not valid_PKCS7_padding(plaintext):
        raise InvalidPadding
    else:
        pad_len = ord(plaintext[-1])
        return plaintext[:-pad_len]
