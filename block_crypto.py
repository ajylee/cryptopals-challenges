import itertools
import random


def strxor(s1, s2):
    return ''.join(chr(ord(_c1) ^ ord(_c2))
               for _c1, _c2 in itertools.izip(s1, s2))


def pad(strn, block_size, pad_str=chr(4)):
    assert len(pad_str) == 1
    return strn + pad_str * (-len(strn) % block_size)


def xor_cipher(data, key):
    _salt = len(data) // len(key) * key + key[:len(data) % len(key)]
    return strxor(data, _salt)


def random_key(length=16):
    return ''.join(chr(random.randint(0, 256))
               for ii in xrange(length))
