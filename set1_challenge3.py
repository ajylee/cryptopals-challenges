import binascii
import string

import toolz

from block_crypto import cipher


def printable(char_or_num):
    if isinstance(char_or_num, int):
        return (31 < char_or_num < 127) or (char_or_num in {9,10,13})
    else:
        return printable(ord(char_or_num))


def score(strn):
    """score_ = (num_letters - num_nonprintable_chars)"""

    for char in strn:
        if not printable(ord(char)):
            return 0

    freqs = toolz.countby(toolz.identity, strn)

    num_letters = sum(freqs.get(letter, 0) for letter in string.ascii_letters + ' \n')

    return num_letters


def _cipher_and_score(data, key):
    _ciphered = cipher(data, key)
    return (key, _ciphered, score(_ciphered))


def top_ciphered(strn, limit=None):
    _ciphered = [_cipher_and_score(strn, chr(ii)) for ii in xrange(256)]
    _filtered = filter(lambda x: x[2] > 0, _ciphered)
    return sorted(_filtered, key=lambda tup: -tup[2])[:limit]


def solve():
    _input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    _i1 = binascii.a2b_hex(_input)


    for key, _ciphered, _score in top_ciphered(_i1, limit=3):
        print _score, repr(key), repr(_ciphered)


if __name__ == '__main__':
    solve()
