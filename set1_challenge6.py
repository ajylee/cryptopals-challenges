
from __future__ import division
import base64
import pprint
import bin_more
import toolz as tz
import itertools

from set1_challenge3 import cipher, top_ciphered


def hamming(s1, s2):
    diff = 0

    for _c1, _c2 in zip(s1, s2):
        diff += bin_more.bit_count(ord(_c1) ^ ord(_c2))

    return diff


def chunks(ss, size, num_chunks):
    return [ss[ii:ii + size]
        for ii in xrange(num_chunks)]



def score_keysizes(strn, max_keysize=40):
    _nchunks = 4  # number of subsequences to use in score
    _results = {} # map keysize to averaged, normalized hamming

    for _trial_keysize in xrange(2, max_keysize):
        _chunks = chunks(strn, _trial_keysize, _nchunks)
        _tot_hamming = 0
        _ncombs = 0

        for _s1, _s2 in itertools.combinations(_chunks, 2):
            _tot_hamming += float(hamming(_s1, _s2)) / _trial_keysize
            _ncombs += 1

        _results[_trial_keysize] = _tot_hamming / _ncombs

    return _results


def test_hamming():
    a = 'this is a test'
    b = 'wokka wokka!!!'

    assert hamming(a, b) == 37


def solve_keysize(ss):
    scores = score_keysizes(ss)

    for _size, _score in tz.take(3, sorted(scores.items(),
                                           key = lambda pair: pair[1])):
        print _size, _score


def get_key_part(ss):
    top3 = top_ciphered(ss, limit=3)
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
    return cipher(ss, key)


def test_breakup_stitch():
    with open('6.txt', 'r') as fil:
        ss = base64.b64decode(fil.read())

    divisor = 8
    test_string = ss #'etubeontub' * 4
    _separated = breakup_by_mod(test_string, divisor)
    assert ''.join(tz.interleave(_separated)) == test_string, _separated


if __name__ == '__main__':
    test_hamming()
    test_breakup_stitch()

    with open('6.txt', 'r') as fil:
        ss = base64.b64decode(fil.read())

    solve_keysize(ss) # conclusion: size is most likely 6

    #for keysize in xrange(2, 8):
    #    solved = solve_code(ss, keysize=6)
    #print repr(solved)
