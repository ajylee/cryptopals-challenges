# NB: Must start hmac-server.rb first

from __future__ import division
import os
import time
import urllib2
import binascii
import logging
import math as ma
import random
import toolz as tz
from infer_difference import InferenceSystem

PORT = 9567

HMAC_SIZE = 20

chars = bytearray(xrange(256))


class NoDifferenceException(Exception):
    pass

class Success(Exception):
    def __init__(self, value):
        self.value = value

class Fail(Exception):
    def __init__(self, value):
        self.value = value


def random_fname():
    dirname = './challenge-data'
    fname = os.path.join(dirname,
                       random.choice(os.listdir(dirname)))

    return fname


def set_sleep_time(port, sleep_time):
    template = ('http://localhost:{port}/set_sleep_time?'
                'sleep_time={sleep_time}')

    urllib2.urlopen(template.format(port=port,
                                    sleep_time=sleep_time))



def mk_url(port, filename, signature):
    template = ('http://localhost:{port}/test?'
                'file={filename}&signature={signature}')
    return template.format(port=port,
                           filename=filename,
                           signature=signature)


def significantly_long_chall31(interval):
    # Whether time interval is significantly long for
    # challenge 31. Fails for 32 (as desired).
    return abs(interval) > .030


def url_get(port, filename, signature):
    start = time.time()

    try:
        return_code = urllib2.urlopen(mk_url(port, filename, signature))
        success = True
    except urllib2.HTTPError, data:
        success = False

    return success, time.time() - start



def solve_byte(oracle, significantly_long):
    t0 = None
    prev_byte = None

    for bb in xrange(0x0100):
        t1 = oracle(bb)

        if t0 is not None and significantly_long(t1 - t0):
            if t1 > t0:
                return bb
            else:
                return prev_byte
        else:
            t0 = t1
            prev_byte = bb
            continue
    else:
        raise NoDifferenceException, 'no differences in guesses found'


def solve_hash_chall31(port, filename):
    curr_hash = bytearray(HMAC_SIZE * [0])

    for ii in xrange(len(curr_hash)):
        _new_guess = bytearray(curr_hash)

        def oracle(bb):
            _new_guess[ii] = bb
            success, time = url_get(port, filename, binascii.hexlify(_new_guess))
            if success:
                raise Success(_new_guess)
            else:
                return time

        try:
            curr_hash[ii] = solve_byte(oracle, significantly_long_chall31)
        except Success as s:
            return s.value
        except NoDifferenceException:
            raise Fail(curr_hash)

        logging.info(repr(binascii.hexlify(curr_hash)))
    else:
        raise Fail


def solve_hash_chall32(port, filename):
    curr_hash = bytearray(HMAC_SIZE)

    for ii in xrange(len(curr_hash)):
        _new_guess = bytearray(curr_hash)

        def oracle(bb):
            _new_guess[ii] = bb
            success, time = url_get(port, filename, binascii.hexlify(_new_guess))
            if success:
                raise Success(_new_guess)
            else:
                return time

        try:
            curr_hash[ii] = InferenceSystem(oracle, chars).infer_best_choice()
        except Success as s:
            return s.value

        logging.info(repr(binascii.hexlify(curr_hash[:ii+1])))
    else:
        raise Fail(curr_hash)


def test_significantly_long():
    set_sleep_time(PORT, 0.050)
    fname = random_fname()

    def diff(b0, b1):
        s0, s1 = bytearray(HMAC_SIZE), bytearray(HMAC_SIZE)
        s0[0], s1[0] = b0, b1
        _, t0 = url_get(PORT, fname, s0)
        _, t1 = url_get(PORT, fname, s1)
        return t1 - t0

    assert any(
        significantly_long_chall31(diff(b0, b1))
        for b0, b1 in tz.sliding_window(2, xrange(256)))


def solve31():
    fname = random_fname()
    set_sleep_time(PORT, 0.050)
    solved_hmac = solve_hash_chall31(PORT, fname)
    assert url_get(PORT, fname, binascii.hexlify(solved_hmac))[0]


def test_failure():
    fname = random_fname()
    set_sleep_time(PORT, 0.005)
    try:
        solve_hash_chall31(PORT, fname)
        raise AssertionError, 'chall 31 solution should fail for sleep time 0.005'
    except Fail:
        logging.info('Test failure of chall 31 solution successful')


def solve32():
    fname = random_fname()
    set_sleep_time(PORT, 0.005)
    solved_hmac = solve_hash_chall32(PORT, fname)
    assert url_get(PORT, fname, binascii.hexlify(solved_hmac))[0]


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    test_significantly_long()
    test_failure()

    import infer_difference
    logging.getLogger(infer_difference.__name__).setLevel(logging.INFO)

    solve31()
    solve32()
