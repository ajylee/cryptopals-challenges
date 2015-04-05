
import base64
import number_theory as nt
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
    """Average of n in the form (int(n), n % 1.)"""

    f = ((a[0] + b[0]) % 2) / 2. + (a[1] + b[1]) / 2.

    return ((a[0] + b[0]) // 2 + int(f), f % 1.)


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
                
        print repr(long_to_bytes(ubound[0]))

    assert (ubound[0] - lbound[0]) + (ubound[1] - ubound[0]) < 1.

    return long_to_bytes(lbound[0] + int(lbound[1] > 0))
    

def test_solve_message():
    message = base64.b64decode(
        'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3'
        'VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==') #[:10]

    pubkey, privkey = keygen(BLOCK_SIZE)

    ciphertext = encrypt(pubkey, message)

    oracle = parity_oracle(privkey)

    print repr(solve_message(oracle, pubkey, ciphertext))
    

if __name__ == '__main__':
    test_solve_message()
