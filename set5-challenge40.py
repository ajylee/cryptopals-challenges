import toolz as tz
import toolz.curried as tzc
import operator
import math as ma
from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_rsa import keygen, encrypt, decrypt, BLOCK_SIZE

# CRT
# ====
#
# result =
#   (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
#   (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
#   (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
#
#
# c_0, c_1, c_2 are the three respective residues mod
# n_0, n_1, n_2
#
# m_s_n (for n in 0, 1, 2) are the product of the moduli
# EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
#
# N_012 is the product of all three moduli


def drop_at(n, seq):
    """Drop the nth element"""
    return seq[:n] + seq[n + 1:]


product = tzc.reduce(operator.mul)


def solve_plaintext(pubkeys, ciphertexts):
    N = tuple(tz.pluck(1, pubkeys))
    C = map(bytes_to_long, ciphertexts)
    M_s = [product(drop_at(ii, N)) for ii in xrange(3)]

    assert M_s[1] == N[0] * N[2]
    assert M_s[0] == N[1] * N[2]
    assert M_s[2] == N[0] * N[1]

    assert len(C) == len(N) == 3
    assert all(e == 3 for e in tz.pluck(0, pubkeys))

    message_cubed = sum(c * m_s * nt.invmod(m_s, n)
                        for c, m_s, n in zip(C, M_s, N)) % product(N)

    return long_to_bytes(nt.long_root(message_cubed, 3))


def test_solve_plaintext():
    K = [keygen(BLOCK_SIZE) for _ in xrange(3)]
    pubkeys = tuple(tz.pluck(0, K))

    m = 'this is secret'

    assert len(m) <= BLOCK_SIZE

    C = [encrypt(pubkey, m) for pubkey in pubkeys]
    assert all(decrypt(privkey, c) == m for c, privkey in
               zip(C, tz.pluck(1, K)))

    assert solve_plaintext(pubkeys, C) == m


if __name__ == '__main__':
    test_solve_plaintext()
