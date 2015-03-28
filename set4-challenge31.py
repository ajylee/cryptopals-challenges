# must start hmac-server.rb first

import time
import urllib2
import binascii
import logging


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


def significantly_long(interval):
    return abs(interval) > .030


def url_get(port, filename, signature):
    start = time.time()

    try:
        return_code = urllib2.urlopen(mk_url(port, filename, signature))
        success = True
    except urllib2.HTTPError, data:
        success = False

    return success, time.time() - start


def solve_byte(oracle):
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


def solve_hash(port, filename):
    curr_hash = bytearray(HMAC_SIZE * [0])

    for ii in xrange(len(curr_hash)):
        _new_guess = bytearray(curr_hash)

        def oracle(bb):
            _new_guess[ii] = bb
            return url_get(port, filename, binascii.hexlify(_new_guess))

        curr_hash[ii] = solve_byte(oracle)
        logging.info(repr(binascii.hexlify(curr_hash)))

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

    assert significantly_long(t1-t0)


def solve31():
    set_sleep_time(PORT, 0.050)
    solved_hmac = solve_hash(PORT, TestData.fname)
    assert url_get(PORT, TestData.fname, binascii.hexlify(solved_hmac))[0]

    
def test_failure():
    import nose.tools
    set_sleep_time(PORT, 0.005)
    solved_hmac = nose.tools.assert_raises(ValueError,
                                           solve_hash, PORT, TestData.fname)


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    test_significantly_long()
    #solve31()
    test_failure()
