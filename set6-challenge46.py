
import base64
import number_theory as nt
import logging
import toolz as tz
from my_rsa import (keygen, encrypt, decrypt, BLOCK_SIZE,
                    long_to_bytes, bytes_to_long)

def last_bit(ss):
    return ord(ss[-1]) & 1


def parity_oracle(privkey):
    """Whether decrypted text is even"""
    def _oracle(ciphertext):
        return last_bit(decrypt(privkey, ciphertext)) == 0

    return _oracle


def average(a, b):
    """Average of a,b in Split Form

    E.g. n in Split Form is (int(n), n % 1.)"""

    f = ((a[0] + b[0]) % 2) / 2. + (a[1] + b[1]) / 2.

    return ((a[0] + b[0]) // 2 + int(f), f % 1.)


def difference_as_float(a, b):
    """Difference of a, b in Split Form

    (see docstring for average)

    """

    return (a[0] - b[0]) + (a[1] - b[1])


def solve_message(is_even, pubkey, ciphertext):
    e, n = pubkey

    lbound = (0, 0)
    ubound = (n, 0)

    c = bytes_to_long(ciphertext)

    for ii in xrange(1, len(ciphertext) * 8 + 1):
        modified_ciphertext = long_to_bytes(
            nt.modexp(2**ii, *pubkey) * c % n
        )

        even = is_even(modified_ciphertext)

        mid_point = average(lbound, ubound)

        if even:
            ubound = mid_point
        else:
            lbound = mid_point
                
        logging.info(repr(long_to_bytes(ubound[0])))

    assert difference_as_float(ubound, lbound) < 1.

    return long_to_bytes(ubound[0])
    

def test_solve_message():
    message = base64.b64decode(
        'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3'
        'VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==') #[:10]

    pubkey, privkey = keygen(BLOCK_SIZE)

    ciphertext = encrypt(pubkey, message)

    oracle = parity_oracle(privkey)

    assert solve_message(oracle, pubkey, ciphertext) == message
    

if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    test_solve_message()
