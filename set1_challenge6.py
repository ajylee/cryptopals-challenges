
from __future__ import division
import base64
import binascii
import pprint
import bin_more
import toolz as tz
import itertools

from set1_challenge3 import top_ciphered
from block_crypto import xor_cipher, chunks
from set1_challenge5 import extra

LOG_KEY_SIZE = 1
LOG_KEY_PART = 0


def hamming(s1, s2):
    diff = 0

    for _c1, _c2 in zip(s1, s2):
        diff += bin_more.bit_count(ord(_c1) ^ ord(_c2))

    return diff


def average_hamming(chunks_):
    _tot_hamming = 0
    _ncombs = 0
    size = len(chunks_[0]) # all chunks should have same size

    for _s1, _s2 in itertools.combinations(chunks_, 2):
        _tot_hamming += float(hamming(_s1, _s2)) / size
        _ncombs += 1

    return _tot_hamming / _ncombs


def score_keysizes(strn, num_chunks, max_keysize):
    """Generate table of scores for various keysizes

    :param int num_chunks: number of subsequences to use in scoring
    :param int max_keysize: max keysize to try

    For each `keysize`, break `strn` into `num_chunks` chunks of length
    `keysize`. The score is the average Hamming distance between the chunks.

    """
    _results = {} # map keysize to averaged, normalized hamming

    for _trial_keysize in xrange(2, max_keysize):
        _chunks = chunks(strn, _trial_keysize, num_chunks)
        _results[_trial_keysize] = average_hamming(_chunks)

    return _results


def test_hamming():
    a = 'this is a test'
    b = 'wokka wokka!!!'

    assert hamming(a, b) == 37


def solve_keysize(ss, num_chunks=6, max_keysize=40):
    scores = score_keysizes(ss, num_chunks, max_keysize)
    _sorted = sorted(scores.items(), key = lambda pair: pair[1])

    if LOG_KEY_SIZE:
        for _size, _score in tz.take(3, _sorted):
            print _size, _score

    return _sorted[0][0]


def get_key_part(ss):
    top3 = top_ciphered(ss, limit=3)
    if LOG_KEY_PART:
        print '=' * 50
        for key, ss, _score in top3:
            print _score, repr(ss)
            print '-' * 50
    return top3[0][0]


def get_key(ss, keysize):
    return ''.join(
        get_key_part(part) for part in breakup_by_mod(ss, keysize))


def breakup_by_mod(strn, divisor):
    return [ ''.join((tz.take_nth(divisor, tz.drop(nn, strn))))
         for nn in xrange(divisor) ]


def solve_code(ss, keysize):
    key = get_key(ss, keysize)
    return xor_cipher(ss, key)


def test_breakup():
    with open('challenge-data/6.txt', 'r') as fil:
        ss = base64.b64decode(fil.read())

    divisor = 8
    test_string = ss #'etubeontub' * 4
    _separated = breakup_by_mod(test_string, divisor)
    assert ''.join(tz.interleave(_separated)) == test_string, _separated


def test_solve_code():
    _i1, _o = extra()
    ss = binascii.unhexlify(_o)
    keysize = solve_keysize(ss, num_chunks=6, max_keysize=10)
    assert keysize == 6
    _i2 = solve_code(ss, keysize=keysize)
    assert _i2 == _i1


if __name__ == '__main__':
    test_hamming()
    test_breakup()
    test_solve_code()

    with open('challenge-data/6.txt', 'r') as fil:
        ss = base64.b64decode(fil.read())

    keysize = solve_keysize(ss, num_chunks=6, max_keysize=40)
    solved = solve_code(ss, keysize=keysize)

    print
    print '-' * 50
    print 'solution'
    print '-' * 50
    print solved
