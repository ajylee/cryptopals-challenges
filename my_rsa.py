
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
import Crypto.Random
import number_theory as nt
import toolz as tz
import toolz.curried as tzc


BLOCK_SIZE = 128   # bytes

@tz.curry
def partition_str(size, strn):
    for ii in xrange(0, len(strn), size):
        yield strn[ii:ii + size]


def keygen():
    # => p * q has BLOCK_SIZE bytes => Can encrypt 15 byte blocks as 16 byte blocks
    prime_size_bits = 8 * (BLOCK_SIZE / 2) + 1

    #p, q = getPrime(prime_size), getPrime(prime_size)

    e = 3

    et = 0

    while et % e == 0:
        p, q = getPrime(prime_size_bits + 1), getPrime(prime_size_bits)
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


def encrypt_multi(public_key, message):
    # c = m**e%n
    e, n = public_key

    def _encrypt_block(block):
        prepadded = chr(1) + block
        c = str_modexp(prepadded, e, n)
        return chr(0) * (2 * BLOCK_SIZE - len(c)) + c

    return tz.pipe(
        message,
        partition_str(BLOCK_SIZE - 1),
        tzc.map(_encrypt_block),
        ''.join)


def decrypt_multi(private_key, ciphertext):
    # m = c**d%n
    d, n = private_key

    def _decrypt_block(cblock):
        prepadded = str_modexp(cblock, d, n)
        block = prepadded[1:] # remove \x01 pad
        return block

    return tz.pipe(
        ciphertext,
        partition_str(2 * BLOCK_SIZE),
        tzc.map(_decrypt_block),
        ''.join)


def encrypt(public_key, message):
    return str_modexp(message, *public_key)


def decrypt(private_key, ciphertext):
    return str_modexp(ciphertext, *private_key)


def test_rsa():
    pubkey, privkey = keygen()

    message = Crypto.Random.new().read(200)

    c  = encrypt_multi(pubkey, message)
    m1 = decrypt_multi(privkey, c)

    assert m1 == message


def test_rsa_nopad():
    pubkey, privkey = keygen()

    # message must not begin with \x00
    message = chr(1) + Crypto.Random.new().read(15)

    c  = encrypt(pubkey, message)
    m1 = decrypt(privkey, c)

    assert m1 == message


if __name__ == '__main__':
    for ii in xrange(10):
        test_rsa()

    for ii in xrange(10):
        test_rsa_nopad()
