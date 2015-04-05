from __future__ import division
import math as ma
import random
import toolz as tz

import number_theory as nt
from my_rsa import decrypt


ceil = tz.compose(int, ma.ceil)
floor = tz.compose(int, ma.floor)


def pkcs1_oracle(privkey):
    def _oracle(ciphertext):
        plaintext = decrypt(privkey, ciphertext)
        return plaintext.startswith('\x00\x01')


def greatest_int_below(num):
    if num % 1. == 0.:
        return int(num) - 1
    else:
        return floor(num)


def blinding(oracle, pubkey, ciphertext):
    e, n = pubkey
    while True:
        s_0 = random.random_int(2, 1000)
        c_0 = nt.modexp(s_0, e, n)
        if oracle(c_0):
            return s_0, c_0


def num_free_bits(block_size):
    """Number of bits after the 0x00 and 0x01 bytes"""
    return 2 ** (8 * (block_size - 2))


def search_s_1(pubkey, c_0, B):
    e, n = pubkey

    s_1 = n / 3 * B

    while True:
        if oracle(nt.modexp(c_0, s_1, e, n)):
            return s_1

        s_1 += 1


def search_with_multiple_intervals_left(oracle, pubkey, c_0, prev_s):
    e, n = pubkey
    s_i = prev_s + 1

    while True:
        if oracle(c_0 * nt.modexp(s_i, e, n) % n):
            return s_i

        s_i += 1


def search_with_one_interval_left(oracle, pubkey, c_0, (a, b)):
    e, n = pubkey

    while True:
        r_i = random.randint(ceil(2*b * (prev_s - 2*B) / n), 100)
        s_i = random.randint(ceil((2*B + r_i*n) / b),
                             greatest_int_below((3*B + r_i*n) / a))

        if oracle(c_0 * nt.modexp(s_i, e, n) % n):
            return s_i


def search(oracle, block_size, pubkey, ciphertext):
    e, n = pubkey

    B = num_free_bits(block_size)

    s_0, c_0 = blinding(oracle, pubkey, ciphertext)

    s = [0, search_s_1(pubkey, c_0, B)]
    M = [(2*B, 3*B - 1), M_i_of_s_i(B, n, s[1])]

    while len(M[-1]) >= 2:
        prev_M = M[-1]

        s_i = search_with_multiple_intervals_left(oracle, pubkey, c_0, s[-1])

        s.append(s_i)
        M.append(M_i_of_si_i(B, n, s_i, prev_M))

    while True:
        s_i = search_with_one_interval_left(oracle, pubkey, c_0, M[-1][0])
        M_i = M_i_of_si_i(B, n, s_i, prev_M)

        s.append(s_i)
        M.append(M_i)

        a, b = M_i[0]

        if a == b:
            return a * nt.invmod(s_0, n) % n


# eqn 3
# ======

def M_i_abr(B, s_i, a, b, r):
    return (max(a, ceil((2*B + r*n) / s_i)),
            min(b, floor((3*B - 1 + r*n) / s_i)))


def M_i_of_s_i(B, n, s_i, prev_M):
    """Step 3: Narrowing the set of solutions"""

    return = set.union(set(), (

        M_i_abr(B, s_i, a, b, r)

        for r in xrange(
                (a * s_i - 3*B + 1) // n,       # TODO: check division
                (b * s_i - 2*B)     // n + 1)   # TODO: check division

        for (a, b) in prev_M))
