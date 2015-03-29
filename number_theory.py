
import binascii 

def modexp(b, p, m):
    """(b ** p) % m for bignum b"""

    return 


def easy_diffie_hellman():
    return diffie_hellman(p=37, g=5)


def diffie_hellman(p, g):
    a = random() % p
    A = (g ** a) % p
    B = (g ** b) % p
    s = (B ** a) % p
    assert s == (A ** b) % p

    return s

def nist_diffie_hellman():
    p = '''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff'''.translate(bytearray(256), ' ')

    return diffie_hellman(p=binascii.unhexlify(p), g=2)

    
