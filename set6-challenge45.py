import itertools
import binascii
import hashlib
import logging

import Crypto.Random
from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_dsa import (keygen, hash_fn, sign_plus, verify_plus,
                    STANDARD_DSA_PQG, get_privkey_from_k, random_int)


def gen_sig_for_g_as_p_plus_1(dsa_pqg, pubkey, z):
    p, q, g = dsa_pqg
    y = pubkey

    r = nt.modexp(y, z, p) % q
    s = nt.invmod(z, q) * r % q
    return (r, s)


def test_g_as_0():
    logging.info('Testing g as 0')
    logging.info('***************')

    dsa_pqg = STANDARD_DSA_PQG[0], STANDARD_DSA_PQG[1], 0

    message = (
        'For those that envy a MC it can be hazardous to your health\n'
        'So be friendly, a matter of life and death, just like a etch-a-sketch\n')

    pubkey, privkey = keygen(dsa_pqg)

    logging.info('NB - pubkey is very bad')
    logging.info('pubkey = {}, privkey = {}'.format(pubkey, privkey))

    signed = sign_plus(dsa_pqg, privkey, message, strict=False, show_k=False)

    signature = signed[1]
    logging.info('NB - signature is very bad')
    logging.info('signature = {}'.format(signature))

    assert verify_plus(dsa_pqg, pubkey, signed, strict=False)


    logging.info('NB - we can change the message and s (where signature is (r,s)) '
                 'and it still verifies to True')

    random_signed_message = (Crypto.Random.new().read(30),
                             (0, random_int(dsa_pqg[0])))

    logging.info('message = {}'.format(repr(random_signed_message[0])))
    logging.info('signature = {}'.format(random_signed_message[1]))

    assert verify_plus(dsa_pqg, pubkey, random_signed_message, strict=False)


def test_g_as_p_plus_1():
    logging.info('')
    logging.info('Testing g = (p + 1)')
    logging.info('********************')

    p, q = STANDARD_DSA_PQG[0], STANDARD_DSA_PQG[1]
    g = p + 1

    dsa_pqg = p, q, g

    pubkey, privkey = keygen(dsa_pqg)

    z = random_int(p)
    logging.info('Randomly selected z = {}'.format(z))

    message = Crypto.Random.new().read(30)
    signature = gen_sig_for_g_as_p_plus_1(dsa_pqg, pubkey, z)

    assert verify_plus(dsa_pqg, pubkey, (message, signature), strict=False)

    logging.info('From pubkey and z, generated valid signature {}'.format(signature))


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    test_g_as_0()
    test_g_as_p_plus_1()
