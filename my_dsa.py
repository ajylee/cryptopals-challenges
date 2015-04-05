import os
import math as ma
import hashlib
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
import number_theory as nt
from bin_more import bit_count


p = long("""
         800000000000000089e1855218a0e7dac38136ffafa72eda7
         859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
         2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
         ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
         b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
         1a584471bb1
         """.translate(None, ' \n'), 16)

# q is 20 bytes
q = long('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

g = long("""5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
         458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
         322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
         0f5b64c36b625a097f1651fe775323556fe00b3608c887892
         878480e99041be601a62166ca6894bdd41a7054ec89f756ba
         9fc95302291""".translate(None, ' \n'), 16)


hash_fn = hashlib.sha1


def random_int(upper_bound):
    # modexp of random bytes
    # should be cryptographically secure

    num_bytes = bit_count(upper_bound) // 8 + int(upper_bound % 8 != 0)

    while True:
        nn = nt.modexp(bytes_to_long(os.urandom(num_bytes - 1)), 9, upper_bound)
        if nn != 0:
            return nn


def _gen_kr():
    while True:
        k = random_int(q)
        r = nt.modexp(g, k, p) % q

        if r != 0:
            return k, r


def keygen():
    x = random_int(q)
    y = nt.modexp(g, x, p)

    pubkey = y
    privkey = x

    return pubkey, privkey


def sign_plus(privkey, message, show_k):
    x = privkey

    while True:
        k, r = _gen_kr()

        _hash = long(hash_fn(message).hexdigest(), 16)

        s = nt.invmod(k, q) * (_hash + x * r) % q

        if s != 0: 
            signature = (r, s)

            if show_k:
                return (message, signature), k
            else:
                return (message, signature)


def sign(privkey, message):
    return sign_plus(privkey, message, False)


def verify(pubkey, (message, signature)):
    y = pubkey
    r, s = signature

    if not ((0 < s < q) and (0 < r < q)):
        return False

    w = nt.invmod(s, q)
    _hash = long(hash_fn(message).hexdigest(), 16)
    u1 = _hash * w % q
    u2 = r * w % q
    v = nt.modexp(g, u1, p) * nt.modexp(y, u2, p) % p % q

    return v == r


def test_sign_and_verify():
    pubkey, privkey = keygen()

    message = 'hello'

    signed = sign(privkey, message)

    assert verify(pubkey, signed)


if __name__ == '__main__':
    test_sign_and_verify()
