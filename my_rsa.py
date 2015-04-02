
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
import Crypto.Random
import number_theory as nt


def keygen():
    # => p * q has > 16 bytes => Can encrypt 16 byte blocks
    prime_size_bits = 8 * 8 + 1  

    #p, q = getPrime(prime_size), getPrime(prime_size)

    e = 3

    et = 0

    while et % e == 0:
        p, q = getPrime(prime_size_bits), getPrime(prime_size_bits)
        n = p * q  # Your RSA math is modulo n.
        et = (p-1)*(q-1) # (the "totient"). You need this value only for keygen.

    d = nt.invmod(e, et)

    assert (d * e) % et == 1

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
    pubkey, privkey = keygen()

    message = Crypto.Random.new().read(16)

    c  = encrypt(pubkey, message)
    m1 = decrypt(privkey, c)

    assert m1 == message


if __name__ == '__main__':
    test_rsa()
