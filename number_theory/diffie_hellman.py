import binascii
import os
from num_tools import modexp, byte_count


DEBUG = False

NIST_P_HEX = '''
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''.translate(bytearray(xrange(256)), ' \n')

NIST_G = 2


def mod_random(p):
    return long(binascii.hexlify(os.urandom(byte_count(p))), 16) % p


def simple_diffie_hellman(p, g):
    a = mod_random(p)
    b = mod_random(p)
    A = (g ** a) % p
    B = (g ** b) % p
    s = (B ** a) % p
    assert s == (A ** b) % p
    return s


def diffie_hellman(p, g):
    a = mod_random(p)
    b = mod_random(p)
    A = modexp(g, a, p)
    B = modexp(g, b, p)
    s = modexp(B, a, p)

    if DEBUG:
        assert s == modexp(A, b, p)

    return s


def easy_diffie_hellman():
    return simple_diffie_hellman(p=37, g=5)


def nist_diffie_hellman():
    p = NIST_P_HEX
    g = NIST_G
    return diffie_hellman(p=long(p, 16), g=g)
