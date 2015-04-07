from __future__ import division
from math import ceil
import datetime, calendar
import random
import Crypto.Random
import toolz as tz
from my_random import MersenneTwister
import memo
from block_crypto import strxor

from number_theory.num_tools import ceil_div
from set3_challenge23 import untemper


def _get_mt_state(seed):
    mt = MersenneTwister(ii)
    mt.generate_numbers()
    return mt.state


if not memo.__dict__.get('MT_STATES'):
    print 'generating states'
    memo.MT_STATES = [_get_mt_state(ii) for ii in xrange(2**16)]
    print 'done generating states'


def current_timestamp():
    now = datetime.datetime.utcnow()
    return calendar.timegm(now.timetuple())


def _int32_to_bytes(n):
    return [(n >> (8 * ii)) & (2**8 - 1)
            for ii in xrange(4)]


def _strn_to_int32(strn):
    ints = []
    curr_int = 0
    for ii, nn in enumerate(tz.map(ord, strn)):
        if ii > 0 and ii % 4 == 0:
            ints.append(curr_int)
            curr_int = 0

        curr_int |= nn << (8 * (ii % 4))

    if len(strn) % 4 == 0:
        ints.append(curr_int)

    return ints


class MTCipher(object):
    def __init__(self, seed):
        self.seed = seed

    def encrypt(self, text):
        mt = MersenneTwister(self.seed)

        ciphertext = ''

        for ii, byte in enumerate(text):
            if ii % 4 == 0:
                xor_block = _int32_to_bytes(mt.extract_number())

            ciphertext += chr(xor_block[ii % 4] ^ ord(byte))

        return ciphertext

    def decrypt(self, text):
        return self.encrypt(text)


def test_MTCipher():
    mtc = MTCipher(random.randint(0, 2**16 - 1))

    text = 'hello, this is the message'

    assert mtc.decrypt(mtc.encrypt(text)) == text


def solve_mt_key(idx, int32_keystream):
    for key, state in enumerate(memo.MT_STATES):
        if state[idx:idx + len(int32_keystream)] == int32_keystream:
            return key


def snip_to_align(idx, text):
    """Largest substring S s.t. S aligned with 32-bit blocks

    :param idx: the index of selected text within the output stream.
    :param text: selected text to align

    """

    front_cut = (-idx % 4)
    chopped_0 = text[front_cut:]

    chopped_1 = chopped_0[:len(chopped_0) - len(chopped_0) % 4]

    return chopped_1


def test_strn_to_int32():
    assert _int32_to_bytes(_strn_to_int32('abcd')[0]) == [97, 98, 99, 100]


def test_solve_mt_key():
    mtc = MTCipher(random.randint(0, 2**16 - 1))

    random_pad = Crypto.Random.new().read(random.randint(0, 300))
    known_text = 'hello, this is the message.'
    plaintext = random_pad + known_text

    raw_ciphertext = mtc.encrypt(plaintext)

    ciphertext = raw_ciphertext[-len(known_text):]
    prepad_len = len(raw_ciphertext) - len(known_text)
    
    keystream_part = strxor(snip_to_align(prepad_len, ciphertext),
                            snip_to_align(prepad_len, known_text))

    idx = ceil_div(prepad_len, 4)
    key = solve_mt_key(idx, map(untemper, _strn_to_int32(keystream_part)))

    assert key == mtc.seed


if __name__ == '__main__':
    test_strn_to_int32()
    test_MTCipher()
    test_solve_mt_key()
