from __future__ import division
import math as ma
from my_rsa import decrypt
import number_theory as nt
import random


def pkcs1_oracle(privkey):
    def _oracle(ciphertext):
        plaintext = decrypt(privkey, ciphertext)
        return plaintext.startswith('\x00\x01')


def blinding(oracle, pubkey, ciphertext):
    e, n = pubkey
    while True:
        s_0 = random.random_int(2, 1000)
        c_0 = nt.modexp(s_0, e, n)
        if oracle(c_0):
            return c_0


def num_free_bits(block_size):
    """Number of bits after the 0x00 and 0x01 bytes"""
    return 2 ** (8 * (block_size - 2))


def search_s_1(pubkey, B):
    e, n = pubkey

    s_1 = n / 3 * B

    while True:
        if oracle(nt.modexp(s_1, e, n)):
            return s_1

        s_1 += 1


def search_with_multiple_intervals_left(s ):



# eqn 3
# ======

def M_i_abr(B, s_i, a, b, r):
    return (max(a, ma.ceil((2*B + r*n) / s_i)),
            min(b, ma.floor((3*B - 1 + r*n) / s_i)))


def narrow_solutions(block_size, n, s, len_M):
    """step 3"""

    B = num_free_bits(block_size)

    M = [(2*B, 3*B - 1)] + [None] * (len_M - 1)

    for ii in xrange(1, len_M):

        M[ii] = set.union(set(), (
            M_i_abr(B, s[ii], a, b, r)
            for r in xrange(
                    (a * s[ii] - 3*B + 1) // n,       # TODO: check division
                    (b * s[ii] - 2*B)     // n + 1)   # TODO: check division

            for (a, b) in M[ii-1]))
