from __future__ import division
from math import ceil
import toolz as tz
from my_random import MersenneTwister


def invert_left(y, shift, magic_number):
    bit_mask = 2**shift - 1

    ans = 0
    for ii in xrange(int(ceil(32 / shift))):
        ans |= (y ^ ((ans << shift) & magic_number)) & (bit_mask << (ii * shift))

    return ans


def invert_right(y, shift):
    bit_mask = (2**32 - 1) - (2**(32 - shift) - 1)
    ans = 0
    for ii in xrange(int(ceil(32 / shift))):
        ans |= (y ^ (ans >> shift)) & (bit_mask >> (ii * shift))

    return ans


def untemper(y):
    return tz.thread_first(
        y,
        (invert_right, 18),
        (invert_left, 15, 4022730752),
        (invert_left, 7, 2636928640),
        (invert_right, 11))


def splice_state_from_fresh_mt_output(prns):
    # NOTE: mt must be at index 0.

    spliced_mt = MersenneTwister(0)

    for ii, prn in enumerate(prns):
        spliced_mt.state[ii] = untemper(prn)

    return spliced_mt


def test_invert_right():
    y = 0x7eab32b3
    shift = 11
    assert invert_right(y ^ (y >> shift), shift) == y


def test_invert_left():
    y = 0xfe1b3d79
    shift = 11
    magic_number = 2636928640
    assert invert_left(y ^ ((y << shift) & magic_number), shift, magic_number) == y


def test_splice():
    mt = MersenneTwister(0x3ab3c179)
    prns = [mt.extract_number() for ii in xrange(len(mt.state))]

    spliced_mt = splice_state_from_fresh_mt_output(prns)

    for ii in xrange(len(mt.state)):
        assert mt.extract_number() == spliced_mt.extract_number()


if __name__ == '__main__':
    test_invert_right()
    test_invert_left()
    test_splice()
