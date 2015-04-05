import toolz as tz
import random
import number_theory as nt
from my_rsa import (keygen, encrypt, decrypt,
                    long_to_bytes, bytes_to_long, BLOCK_SIZE)


def server_oracle(privkey, c0):
    def _oracle(c1):
        if c0 == c1:
            # submission of original ciphertext not permitted
            return None
        else:
            return decrypt(privkey, c1)

    return _oracle


def gen_s(n):
    """Generate s > 1 (mod n) s.t. n % s != 0.

    If s divides n, then invmod(s, n) will fail. However, note that in that case
    we trivially recover the private key.)

    """

    s = 1
    while n % s == 0:
        s = random.randint(2, n - 1)

    return s


def recover_plaintext(oracle, pubkey, ciphertext):
    e, n = pubkey

    s = gen_s(n)

    c0 = bytes_to_long(ciphertext)

    c1 = (nt.modexp(s, e, n) * c0) % n

    p1 = tz.pipe(c1, long_to_bytes, oracle, bytes_to_long)

    assert nt.modexp(p1, *pubkey) == c1

    p0 = (nt.invmod(s, n) * p1) % n

    return long_to_bytes(p0)


def test_recover_plaintext():
    plaintext = "{time: 1356304276, social: '555-55-5555'}"

    pubkey, privkey = keygen(BLOCK_SIZE)

    ciphertext = encrypt(pubkey, plaintext)

    _oracle = server_oracle(privkey, ciphertext)

    assert recover_plaintext(_oracle, pubkey, ciphertext) == plaintext


if __name__ == '__main__':
    test_recover_plaintext()
