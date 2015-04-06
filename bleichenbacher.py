from __future__ import division
import binascii
import random
import logging
from itertools import count
import toolz as tz

from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_rsa import decrypt


logger = logging.getLogger(__name__)


def ceil_div(nn, dd):
    div, mod = divmod(nn, dd)
    return div + int(mod != 0)


def _reinstate_initial_0s(plaintext_without_0s, block_size):
    # NOTE: The (big-endian) decrypted block has its initial zeros removed.
    return ((block_size - len(plaintext_without_0s)) * chr(0)
            + plaintext_without_0s)


def pkcs1_oracle(privkey, block_size):
    def _oracle(ciphertext):
        plaintext_without_initial_0s = decrypt(privkey, ciphertext)
        plaintext = _reinstate_initial_0s(plaintext_without_initial_0s, block_size)
        return plaintext.startswith('\x00\x02')

    return _oracle


def derive_B(block_size):
    """2 to the number of bits after the 0x00 and 0x02 bytes"""
    return 2 ** (8 * (block_size - 2))


# Step 1; Initialize s_0, M_0, s_1, M_1
# ======================================

def init_s_0_c_0(oracle, pubkey, c):
    """
    :param c: ciphertext as bignum; not necessary if c already conforms
    """
    e, n = pubkey

    if oracle(long_to_bytes(c)):
        return 1, c
    else:
        while True:
            s_0 = random.randint(2, 2**16)
            c_0 = c * nt.modexp(s_0, e, n) % n
            if oracle(long_to_bytes(c_0)):
                return s_0, c_0


def derive_s_1_M_1(oracle, pubkey, B, c_0):
    e, n = pubkey

    s_1 = search_s_1(oracle, pubkey, B, c_0)

    M_0 = {(2*B, 3*B - 1)}
    M_1 = M_i_of_s_i(B, n, s_1, M_0)

    assert len(M_1) >= 1

    return s_1, M_1


# Step 2; Search for pkcs1 conformance
# ======================================

def search_s_1(oracle, pubkey, B, c_0):
    # step_2a
    e, n = pubkey
    return search_s_i_linear(oracle, pubkey, c_0,
                             start = ceil_div(n, 3*B))


def search_s_i_linear(oracle, pubkey, c_0, start):
    e, n = pubkey

    for s_i in count(start):
        if s_i % 5000 == 0:
            logger.info('Searching linearly for s_i ... {}' .format(s_i))
        if oracle(long_to_bytes(c_0 * nt.modexp(s_i, e, n) % n)):
            logger.info('Found s_i = {}'.format(s_i))
            return s_i


def search_s_i_logarithmic(oracle, pubkey, B, c_0, prev_s, (a, b)):
    e, n = pubkey

    r_lbound = ceil_div(2 * (b*prev_s - 2*B), n)

    for r_i in count(r_lbound):
        s_lbound, s_ubound = (ceil_div(2*B + r_i*n, b),
                              ceil_div(3*B + r_i*n, a))

        for s_i in long_xrange(s_lbound, s_ubound):
            if oracle(long_to_bytes(c_0 * nt.modexp(s_i, e, n) % n)):
                return s_i


# Step 3; Narrowing set of solutions
# ===================================

def long_xrange(initial, final):
    for ii in count(initial):
        if ii < final:
            yield ii
        else:
            break


def M_i_abr(B, n, s_i, a, b, r):
    return (max(a, ceil_div(2*B + r*n, s_i)),
            min(b, (3*B - 1 + r*n) // s_i))


def log_and_check_M(M_im1, M_i):
    len_M_i = len(M_i)

    assert len_M_i > 0

    if len_M_i > 1:
        logger.info("{} intervals left".format(len_M_i))
    elif len_M_i == 1 and len(M_im1) > 1:
        logger.info("Reached single interval")


def M_i_of_s_i(B, n, s_i, prev_M):
    """Step 3: Narrowing the set of solutions"""

    def r_range(a, b):
        lbound = ceil_div(a*s_i - 3*B + 1, n)
        ubound = (b*s_i - 2*B) // n
        return long_xrange(lbound, ubound + 1)

    M_i = {M_i_abr(B, n, s_i, a, b, r)
           for (a, b) in prev_M
           for r in r_range(a, b)}

    log_and_check_M(prev_M, M_i)

    return M_i


# Put it together
# ================


def next_s_M(oracle, pubkey, B, c_0, (s_j, M_j)):
    e, n = pubkey

    if len(M_j) > 1:
        s_jp1 = search_s_i_linear(oracle, pubkey, c_0, s_j + 1)
    else:
        s_jp1 = search_s_i_logarithmic(oracle, pubkey,
                                       B, c_0, s_j, tz.first(M_j))

    M_jp1 = M_i_of_s_i(B, n, s_jp1, M_j)

    return (s_jp1, M_jp1)


def search(oracle, block_size, pubkey, ciphertext):
    e, n = pubkey
    B = derive_B(block_size)

    s_0, c_0 = init_s_0_c_0(oracle, pubkey, bytes_to_long(ciphertext))

    logger.info('derive_s_1_M_1')
    s_1, M_1 = derive_s_1_M_1(oracle, pubkey, B, c_0)

    _next_s_M = tz.partial(next_s_M, oracle, pubkey, B, c_0)

    for s_i, M_i in tz.iterate(_next_s_M, (s_1, M_1)):
        if len(M_i) == 1:

            a, b = tz.first(M_i)

            if a == b:
                plaintext_int = a * nt.invmod(s_0, n) % n
                return _reinstate_initial_0s(long_to_bytes(plaintext_int), block_size)
