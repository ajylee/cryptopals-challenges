from __future__ import division
import binascii
import random
import logging
import toolz as tz

from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_rsa import decrypt

from memo import memo

logger = logging.getLogger(__name__)

class DebugMem:
    count = 1

def ceil_div(nn, dd):
    return nn // dd + int(nn % dd != 0)


def inc(x): return x + 1


def greatest_int_below_div(nn, dd):
    _floor = nn // dd
    if nn % dd == 0:
        return _floor - 1
    else:
        return _floor


def _reinstate_initial_0s(plaintext_without_0s, block_size):
    # NOTE: The (big-endian) decrypted block has its initial zeros removed.
    return ((block_size - len(plaintext_without_0s)) * chr(0)
            + plaintext_without_0s)


def pkcs1_oracle(privkey, block_size):
    def _oracle(ciphertext):
        plaintext_without_initial_0s = decrypt(privkey, ciphertext)
        plaintext = _reinstate_initial_0s(plaintext_without_initial_0s, block_size)
        return plaintext.startswith('\x00\x01')

    return _oracle


def init_s_0_c_0(oracle, pubkey, c):
    """
    :param c: ciphertext as bignum
    """
    e, n = pubkey

    while True:
        s_0 = random.randint(2, 2**16)
        c_0 = c * nt.modexp(s_0, e, n) % n
        if oracle(long_to_bytes(c_0)):
            return s_0, c_0


def derive_s_1_M_1(oracle, block_size, pubkey, c_0):
    e, n = pubkey
    B = num_free_bits(block_size)

    s_1 = memo('search_s_1', lambda : search_s_1(oracle, pubkey, c_0, B))

    M_0 = {(2*B, 3*B - 1)}
    M_1 = M_i_of_s_i(B, n, s_1, M_0)

    assert len(M_1) >= 1

    return s_1, M_1


def num_free_bits(block_size):
    """Number of bits after the 0x00 and 0x01 bytes"""
    return 2 ** (8 * (block_size - 2))


def search_s_1(oracle, pubkey, c_0, B):
    # step_2a
    e, n = pubkey

    for s_1 in tz.iterate(inc, ceil_div(n, 3*B)):
        if oracle(long_to_bytes(c_0 * nt.modexp(s_1, e, n) % n)):
            return s_1


def search_with_multiple_intervals_left(oracle, pubkey, c_0, prev_s):
    e, n = pubkey

    for s_i in tz.iterate(inc, prev_s + 1):
        if s_i % 10000 == 0:
            print s_i
        if oracle(long_to_bytes(c_0 * nt.modexp(s_i, e, n) % n)):
            return s_i


def search_with_one_interval_left(oracle, pubkey, B, c_0, prev_s, (a, b)):
    e, n = pubkey

    r_lbound = ceil_div(2 * (b*prev_s - 2*B), n)
    r_ubound = r_lbound + 20

    for r_i in tz.iterate(inc, r_lbound):
        if r_i > r_ubound:
            break
        s_lbound, s_ubound = (ceil_div(2*B + r_i*n, b),
                              ceil_div(3*B + r_i*n, a))
        print '-' * 50

        for s_i in long_xrange(s_lbound, s_ubound):

            # s_i = random.randint(s_lbound, s_ubound)

            print r_i, s_i

            if oracle(long_to_bytes(c_0 * nt.modexp(s_i, e, n) % n)):
                return s_i


# eqn 3
# ======

def long_xrange(initial, final):
    for ii in tz.iterate(inc, initial):
        if ii < final:
            yield ii
        else:
            break


def M_i_abr(B, n, s_i, a, b, r):
    return (max(a, ceil_div(2*B + r*n, s_i)),
            min(b, (3*B - 1 + r*n) // s_i))


def M_i_of_s_i(B, n, s_i, prev_M):
    """Step 3: Narrowing the set of solutions"""

    ans = set()

    for (a, b) in prev_M:
        lbound = ceil_div(a*s_i - 3*B + 1, n)
        ubound = (b*s_i - 2*B) // n
        for r in long_xrange(lbound, ubound + 1):
            ans.add(M_i_abr(B, n, s_i, a, b, r))


    assert len(ans) >= 0

    return ans


def next_s_M(oracle, block_size, pubkey, c_0, (s_j, M_j)):
    e, n = pubkey
    B = num_free_bits(block_size)

    assert M_j

    if len(M_j) > 1 or True:
        s_jp1 = search_with_multiple_intervals_left(oracle, pubkey, c_0, s_j)
    else:
        s_jp1 = search_with_one_interval_left(oracle, pubkey,
                                              B, c_0, s_j, tz.first(M_j))

    return (s_jp1, M_i_of_s_i(B, n, s_jp1, M_j))


def nomemo(label, thunk):
    return thunk()


def search(oracle, block_size, pubkey, ciphertext):
    e, n = pubkey
    B = num_free_bits(block_size)

    #s_0, c_0 = memo(__name__ + '.init_s_0_c_0',
    #                lambda : init_s_0_c_0(oracle, pubkey, bytes_to_long(ciphertext)))

    s_0, c_0 = 1, bytes_to_long(ciphertext)

    logger.debug('s_1, M_1')
    s_1, M_1 = memo(__name__ + '.derive_s_1_M_1',
                    lambda : derive_s_1_M_1(oracle, block_size, pubkey, c_0))

    _next_s_M = tz.partial(next_s_M, oracle, block_size, pubkey, c_0)

    #DebugMem.count = 1
    #def _next_s_M((s_i, M_i)):
    #    DebugMem.count += 1
    #    return memo(
    #        ('_next_s_M', DebugMem.count),
    #        lambda : next_s_M(oracle, block_size, pubkey, c_0, (s_i, M_i)))


    for s_i, M_i in tz.iterate(_next_s_M, (s_1, M_1)):
        logger.debug('M_i = {}'.format(M_i))

        if len(M_i) == 1:

            a, b = tz.first(M_i)

            if a == b:
                return long_to_bytes(a * nt.invmod(s_0, n) % n)
