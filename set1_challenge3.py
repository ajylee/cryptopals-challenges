

import binascii
import base64
from Crypto.Util.strxor import strxor
import toolz
import string


def cipher(data, key):
    _salt = len(data) // len(key) * key + key[:len(data) % len(key)]
    return strxor(data, _salt)


def score(strn):
    """score_ = (num_letters - num_nonprintable_chars)"""

    freqs = toolz.countby(toolz.identity, strn)

    num_letters = sum(freqs.get(letter, 0) for letter in string.ascii_letters + ' \n')
    num_nonprintable = sum(freqs.get(chr(notletter), 0)
                           for notletter in xrange(32))

    return num_letters - num_nonprintable


def top_ciphered(strn, limit=None):
    _ciphered = [cipher(strn, chr(ii)) for ii in xrange(256)]
    return sorted(_ciphered, key=lambda ss: -score(ss))[:limit]


def solve():
    _input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    _i1 = binascii.a2b_hex(_input)


    for ss in top_ciphered(_i1, limit=3):
        print score(ss), repr(ss)


if __name__ == '__main__':
    solve()
    