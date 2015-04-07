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

    def encrypt_with_random_pad(self, plaintext):
        random_pad = Crypto.Random.new().read(random.randint(0, 300))
        padded = random_pad + plaintext
        return mtc.encrypt(padded)

    def decrypt(self, text):
        return self.encrypt(text)


def test_MTCipher():
    mtc = MTCipher(random.randint(0, 2**16 - 1))

    text = 'hello, this is the message'

    assert mtc.decrypt(mtc.encrypt(text)) == text


def generate_keystream_part(encrypt_fn):
    known_text = 'hello, this is the message.'
    raw_ciphertext = encrypt_fn(known_text)

    ciphertext = raw_ciphertext[-len(known_text):]
    prepad_len = len(raw_ciphertext) - len(known_text)

    byte_keystream_part = strxor(snip_to_align(prepad_len, ciphertext),
                                 snip_to_align(prepad_len, known_text))

    idx = ceil_div(prepad_len, 4)

    int32_keystream = map(untemper, _strn_to_int32(byte_keystream_part))

    return idx, int32_keystream


def solve_mt_key(encrypt_fn):
    idx, int32_keystream = generate_keystream_part(encrypt_fn)

    for key, state in enumerate(memo.MT_STATES):
        if state[idx:idx + len(int32_keystream)] == int32_keystream:
            return key


def detect_and_solve_current_timestamp_mt(encrypt_fn, max_sec_back=3600):
    """Looks back `max_sec_back` in time for a matching MT seed. Returns (True,
    key) on success; else (False, None) if no such seed is found.

    """
    idx, int32_keystream = generate_keystream_part(encrypt_fn)
    timestamp = current_timestamp()

    for time_back in xrange(max_sec_back):
        key = timestamp - time_back
        state = _get_mt_state(key)
        if state[idx:idx + len(int32_keystream)] == int32_keystream:
            return (True, key)
    else:
        return (False, None)


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
    key = solve_mt_key(mtc.encrypt_with_random_pad)
    assert key == mtc.seed


def test_solve_current_timestamp_mt():
    seed = current_timestamp()
    cipher = MTCipher(seed)
    valid, key = detect_and_solve_current_timestamp_mt(
        cipher.encrypt_with_random_pad)

    assert valid and key == seed

    non_timestamp_cipher = MTCipher(1000)

    assert not detect_and_solve_current_timestamp_mt(
        non_timestamp_cipher.encrypt_with_random_pad)[0]


if __name__ == '__main__':
    test_strn_to_int32()
    test_MTCipher()
    test_solve_mt_key()
    test_solve_current_timestamp_mt()
