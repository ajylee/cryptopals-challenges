
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long

import number_theory as nt



def keygen():
    prime_size = 16  # num bits

    p, q = getPrime(prime_size), getPrime(prime_size)

    n = p * q  # Your RSA math is modulo n.

    et = (p-1)*(q-1) # (the "totient"). You need this value only for keygen.
    e = 3
    d = nt.invmod(e, et) % n

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def str_modexp(strn, e, n):
    g = bytes_to_long(strn)
    ll = nt.modexp(g, e, n)
    return long_to_bytes(ll)


def encrypt(public_key, message):
    # c = m**e%n
    e, n = public_key
    return str_modexp(message, e, n)

def decrypt(private_key, ciphertext):
    # m = c**d%n
    d, n = private_key
    return str_modexp(ciphertext, d, n)


def test_rsa():
    # Test this out with a number, like "42".
    # Repeat with bignum primes (keep e=3).

    pubkey, privkey = keygen()

    message = 'Hello, this is the message.'

    c  = encrypt(pubkey, message)
    m1 = decrypt(privkey, c)

    assert m1 == message


if __name__ == '__main__':
    test_rsa()
