import binascii
import hashlib
import number_theory as nt
import logging
from Crypto.Util.number import long_to_bytes, bytes_to_long
from my_dsa import (hash_fn, keygen, sign_plus, sign, verify,
                    p, q, g)


def solve_privkey(pubkey, signed_message):
    message, signature = signed_message

    for _guess_k in xrange(0, 2**16):
        _maybe_privkey = get_privkey_from_k(signed_message, _guess_k)

        if _guess_k % 1000 == 0:
            logging.info('Guessing k = {}'.format(_guess_k))

        if nt.modexp(g, _maybe_privkey, p) == pubkey:
            _maybe_r = nt.modexp(g, _guess_k, p) % q
            _hash = bytes_to_long(hash_fn(message))
            _maybe_s = nt.invmod(_guess_k, q) * (_hash + _maybe_privkey * _maybe_r) % q

            if (_maybe_r, _maybe_s) == signature:
                return _maybe_privkey
    else:
        raise ValueError, 'no valid k found'


def test_solve_privkey():
    message = (
        'For those that envy a MC it can be hazardous to your health\n'
        'So be friendly, a matter of life and death, just like a etch-a-sketch\n')

    pubkey = long("""84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
                  abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
                  e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
                  1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
                  bb283e6633451e535c45513b2d33c99ea17
                  """.translate(None, ' \n'), 16)

    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    signature = (r,s)

    signed = (message, signature)


    # check message, pubkey, signature copied correctly
    assert (bytes_to_long(hash_fn(message))
            == long('d2d0714f014a9784047eaeccf956520045c45265', 16))
    assert verify(pubkey, signed)


    # solve and check
    privkey = solve_privkey(pubkey, signed)

    _, _maybe_signature = sign(privkey, message)
    assert verify(pubkey, (message, _maybe_signature))

    assert (hashlib.sha1(binascii.hexlify(long_to_bytes(privkey))).hexdigest()
            == '0954edd5e0afe5542a4adf012611a91912a3ec16')


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    test_solve_privkey()
