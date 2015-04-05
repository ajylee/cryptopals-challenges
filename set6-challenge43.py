import number_theory as nt
from my_dsa import (hash_fn, keygen, sign_plus, sign, verify,
                    p, q, g)


def get_privkey_from_k((message, signature), k):
    """

        (s * k) - H(msg)
    x = ----------------  mod q
                r

    """

    r, s = signature

    _hash = long(hash_fn(message).hexdigest(), 16)

    x = nt.invmod(r, q) * ((s * k) - _hash) % q

    return x 


def test_get_x_from_k():
    pubkey, privkey = keygen()

    message = 'hello'

    signed, k = sign_plus(privkey, message, show_k=True)

    assert get_privkey_from_k(signed, k) == privkey


if __name__ == '__main__':
    test_get_x_from_k()
