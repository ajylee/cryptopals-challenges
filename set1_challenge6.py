
from __future__ import division
import base64
import pprint
import bin_more
import toolz
import itertools


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

        for _size, _score in toolz.take(3, sorted(scores.items(),
                                                  key = lambda pair: pair[1])):
            print _size, _score


def break_code(ss):
    pass


def solve_code(ss):
    pass


if __name__ == '__main__':
    test_hamming()

    with open('6.txt', 'r') as fil:
        ss = base64.b64decode(fil.read())

    solve_keysize(ss) # conclusion: size is most likely 6
    
    solve_code(ss)