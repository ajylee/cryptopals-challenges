import os
import math as ma
import hashlib
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
import number_theory as nt
from bin_more import bit_count


_p = long("""
          800000000000000089e1855218a0e7dac38136ffafa72eda7
          859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
          2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
          ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
          b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
          1a584471bb1
          """.translate(None, ' \n'), 16)

# q is 20 bytes
_q = long('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)

_g = long("""5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
          458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
          322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
          0f5b64c36b625a097f1651fe775323556fe00b3608c887892
          878480e99041be601a62166ca6894bdd41a7054ec89f756ba
          9fc95302291""".translate(None, ' \n'), 16)


STANDARD_DSA_PQG = (_p, _q, _g)


def hash_fn(message):
    return hashlib.sha1(message).digest()


def random_int(upper_bound):
    # modexp of random bytes
    # should be cryptographically secure

    num_bytes = bit_count(upper_bound) // 8 + int(upper_bound % 8 != 0)

    while True:
        nn = nt.modexp(bytes_to_long(os.urandom(num_bytes - 1)), 9, upper_bound)
        if nn != 0:
            return nn


def _gen_kr(p, q, g, strict):
    while True:
        k = random_int(q)
        r = nt.modexp(g, k, p) % q

        if r != 0 or (not strict):
            return k, r


def keygen(dsa_pqg):
    p, q, g = dsa_pqg
    x = random_int(q)
    y = nt.modexp(g, x, p)

    pubkey = y
    privkey = x

    return pubkey, privkey


def sign_plus(dsa_pqg, privkey, message, strict, show_k):
    p, q, g = dsa_pqg
    x = privkey

    while True:
        k, r = _gen_kr(p, q, g, strict)

        _hash = bytes_to_long(hash_fn(message))

        s = nt.invmod(k, q) * (_hash + x * r) % q

        if s != 0 or (not strict):
            signature = (r, s)

            if show_k:
                return (message, signature), k
            else:
                return (message, signature)


def sign(dsa_pqg, privkey, message):
    return sign_plus(dsa_pqg, privkey, message, strict=True, show_k=False)


def verify(dsa_pqg, pubkey, (message, signature)):
    p, q, g = dsa_pqg
    y = pubkey
    r, s = signature

    if not ((0 < s < q) and (0 < r < q)):
        return False

    w = nt.invmod(s, q)
    _hash = bytes_to_long(hash_fn(message))
    u1 = _hash * w % q
    u2 = r * w % q
    v = nt.modexp(g, u1, p) * nt.modexp(y, u2, p) % p % q

    return v == r


def get_privkey_from_k(dsa_pqg, (message, signature), k):
    """

        (s * k) - H(msg)
    x = ----------------  mod q
                r

    """

    p, q, g = dsa_pqg

    r, s = signature

    _hash = bytes_to_long(hash_fn(message))

    x = nt.invmod(r, q) * ((s * k) - _hash) % q

    return x


# Testing
# ========

def test_sign_and_verify():
    dsa_pqg = STANDARD_DSA_PQG

    pubkey, privkey = keygen(dsa_pqg)

    message = 'hello'

    signed = sign(dsa_pqg, privkey, message)

    assert verify(dsa_pqg, pubkey, signed)


    pubkey_1, privkey_1 = keygen(STANDARD_DSA_PQG)
    wrong_signed = sign(dsa_pqg, privkey_1, message)

    assert not verify(dsa_pqg, pubkey, wrong_signed)


def test_get_privkey_from_k():
    dsa_pqg = STANDARD_DSA_PQG

    pubkey, privkey = keygen(dsa_pqg)

    #message = 'hello'

    message = (
        'For those that envy a MC it can be hazardous to your health\n'
        'So be friendly, a matter of life and death, just like a etch-a-sketch\n')

    signed, k = sign_plus(dsa_pqg, privkey, message, strict=True, show_k=True)

    assert get_privkey_from_k(dsa_pqg, signed, k) == privkey


if __name__ == '__main__':
    test_sign_and_verify()
    test_get_privkey_from_k()
