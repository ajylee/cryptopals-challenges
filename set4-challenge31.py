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


if __name__ == '__main__':
    #signature = bytearray(
    #    b'\xfe\xa8\x1d;`6\x1f\xb8\xda\xb5\x97b\xec\xb1\xe1\xa8\x175>\x8c')
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    set_sleep_time(PORT, 0.050)

    signature = (
        '9198ac704afb4c460fb532da453b7a63362d2b5a'
    )

    s1 = '0000000000000000000000000000000000000000'
    s2 = '9100000000000000000000000000000000000000'

    fname = '20.txt'

    _, t1 = url_get(PORT, fname, s1)
    _, t2 = url_get(PORT, fname, s2)

    assert significantly_long(t2-t1)

    solved_hmac = solve_hash(PORT, fname)
    assert url_get(PORT, fname, binascii.hexlify(solved_hmac))[0]
