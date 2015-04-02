
from Crypto.Util.number import getPrime, long2str, str2long

import number_theory as nt



def keygen():

    prime_size = 16  # num bits

    p, q = getPrime(prime_size), getPrime(prime_size)

    # Let n be p * q.

    n = p * q  # Your RSA math is modulo n.

    et = (p-1)*(q-1) % n # (the "totient"). You need this value only for keygen.
    e = 3
    d = nt.invmod(e, et) % n

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def str_modexp(strn, u, p):
    g = str2long(strn)
    ll = nt.modexp(g, e, n)
    return long2str(ll)


# To encrypt: . To decrypt:

def encrypt(public_key, message):
    # c = m**e%n
    e, n = public_key
    return str_modexp(message, e, n)

def decrypt(private_key, ciphertext):
    # m = c**d%n
    d, n = private_key
    return str_modexp(ciphertext, d, n)



    # Test this out with a number, like "42".
    # Repeat with bignum primes (keep e=3).
