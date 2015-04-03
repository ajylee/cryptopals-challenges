import toolz as tz
import toolz.curried as tzc
import operator
from Crypto.Util.number import long_to_bytes, bytes_to_long
from my_rsa import keygen, encrypt_nopad

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


def _cube_root(nn):
    return long(round(nn ** (1./3.)))


def solve_plaintext(pubkeys, ciphertexts):
    N = tuple(tz.pluck(1, pubkeys))
    C = ciphertexts
    M_s = [product(drop_at(ii, n)) for ii in xrange(3)]

    assert len(c) == len(n) == 3
    assert all(e == 3 for e, _ in pubkeys)

    message_cubed = sum(map(bytes_to_long, c))

    return long_to_bytes(_cube_root(message_cubed))


def test_solve_plaintext():
    k = [keygen() for _ in xrange(3)]
    pubkeys = tz.pluck(0, k)

    m = 'hello'

    c = [encrypt_nopad(pubkey, m) for pubkey, privkey in k]

    print repr(solve_plaintext(pubkeys, c))



if __name__ == '__main__':
    test_solve_plaintext()
