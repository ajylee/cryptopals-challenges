# must start hmac-server.rb first

from __future__ import division
import time
import urllib2
import binascii
import logging
import math as ma
import numpy as np
from statistics import uncertainty_of_mean


PORT = 9567

HMAC_SIZE = 20


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
        success, t1 = oracle(bb)

        if t0 is not None and significantly_long(t1 - t0):
            if t1 > t0:
                return bb
            else:
                return prev_byte
        elif success:
            return bb
        else:
            t0 = t1
            prev_byte = bb
            continue
    else:
        raise ValueError, 'no differences in guesses found'


def solve_hash_chall31(port, filename):
    curr_hash = bytearray(HMAC_SIZE * [0])

    for ii in xrange(len(curr_hash)):
        _new_guess = bytearray(curr_hash)

        def oracle(bb):
            _new_guess[ii] = bb
            return url_get(port, filename, binascii.hexlify(_new_guess))

        curr_hash[ii] = solve_byte(oracle, significantly_long_chall31)
        logging.info(repr(binascii.hexlify(curr_hash)))

    return curr_hash


def stats(timer):
    """Gives the significant time interval and the number
    of trials necessary to achieve it.

    :param timer: timer(hmac_hash) -> time

    """

    post_pad = '\x00' * (HMAC_SIZE - 1)
    zero_times = []     # collection of times for byte 0x00
    running_total = [0] * 0x100
    count = 0

    while True:
        largest_diff = 0

        for bb in xrange(0x100):
            _t = timer(chr(bb) + post_pad)

            if bb == 0:
                zero_times.append(_t)

            running_total[bb] += _t

            largest_diff = max(largest_diff,
                               running_total[bb] - running_total[0])

        count += 1

        logging.info('count {}'.format(count))

        if count > 3:
            unc = np.std(zero_times, ddof=1)
            unc_of_unc = unc / (2. * ma.sqrt(count - 1))

            lhs = 5 * (unc + unc_of_unc) * ma.sqrt(HMAC_SIZE * count)
            if lhs < largest_diff:
                significant_interval = (largest_diff / count) - (unc + unc_of_unc)

                base_necessary_trials = 4 * (unc + unc_of_unc) / significant_interval

                logging.info('base_necessary_trials: {}, sig interval: {}'
                             .format(base_necessary_trials, significant_interval))

                return base_necessary_trials, significant_interval
            else:
                logging.info('lhs: {}'.format(lhs))
                logging.info('rhs: {}'.format(largest_diff))


def solve_hash_chall32(port, filename, starting_bytes=''):
    def base_oracle(h): return url_get(port, filename, binascii.hexlify(h))

    #base_necessary_trials, significant_interval = stats(
    #    lambda h: base_oracle(h)[1])

    #base_necessary_trials, significant_interval = 2, 0.003
    significant_interval = 0.0035
    num_trials = lambda ii: max(3, ii)
    #num_trials = lambda ii: (3 + int(ma.ceil(ii * .8)))

    if starting_bytes:
        curr_hash = bytearray(starting_bytes + '\x00' * (-len(starting_bytes) % HMAC_SIZE))
    else:
        curr_hash = bytearray([0] * HMAC_SIZE) 

    for ii in xrange(len(starting_bytes), len(curr_hash)):
        _new_guess = bytearray(curr_hash)
        logging.info('num trials {}'.format(num_trials(ii)))

        def oracle(bb):
            _new_guess[ii] = bb
            total_time = 0
            for _ in xrange(num_trials(ii)):
                success, _t = base_oracle(_new_guess)
                total_time += _t
            return success, total_time / num_trials(ii) 

        curr_hash[ii] = solve_byte(oracle, lambda t: abs(t) > significant_interval)
        logging.info(repr(binascii.hexlify(curr_hash[:ii+1])))

    return curr_hash


class TestData:
    actual_signature = (
        '9198ac704afb4c460fb532da453b7a63362d2b5a'
    )

    s0 = '0000000000000000000000000000000000000000'
    s1 = '9100000000000000000000000000000000000000'

    fname = 'challenge-data/20.txt'


def test_significantly_long():
    set_sleep_time(PORT, 0.050)

    _, t0 = url_get(PORT, TestData.fname, TestData.s0)
    _, t1 = url_get(PORT, TestData.fname, TestData.s1)

    assert significantly_long_chall31(t1-t0)


def solve31():
    set_sleep_time(PORT, 0.050)
    solved_hmac = solve_hash_chall31(PORT, TestData.fname)
    assert url_get(PORT, TestData.fname, binascii.hexlify(solved_hmac))[0]


def test_failure():
    import nose.tools
    set_sleep_time(PORT, 0.005)
    solved_hmac = nose.tools.assert_raises(ValueError,
                                           solve_hash_chall31,
                                           PORT, TestData.fname)


def solve32():
    set_sleep_time(PORT, 0.005)
    #start = binascii.unhexlify('9198ac704afb4c460fb532da453b7a63362d')
    solved_hmac = solve_hash_chall32(PORT, TestData.fname)
    assert url_get(PORT, TestData.fname, binascii.hexlify(solved_hmac))[0]


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    test_significantly_long()
    #test_failure()
    #solve31()
    solve32()
