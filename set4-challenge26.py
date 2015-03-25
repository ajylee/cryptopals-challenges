from __future__ import division
import Crypto.Random
from cookies import CookieSystem
from bin_more import ords as str_to_ords
from block_crypto import CTR, strxor

BLOCK_SIZE = 16

def mk_CTR_CookieSystem(block_size):
    # block_size only used for setting CTR key and nonce
    rand_io = Crypto.Random.new()
    key = rand_io.read(block_size)
    nonce = str_to_ords(rand_io.read(block_size // 2))
    cipher = CTR(key, nonce)
    return CookieSystem(cipher)


def mk_admin_data(process_fn):
    t1 = 'A' * 20
    t2 = 'B' * 20

    c1 = process_fn(t1)
    c2 = process_fn(t2)

    for idx in xrange(len(c1) - len(t1)):
        maybe_key = strxor(c1[idx: idx + len(t1)], t1)
        if strxor(maybe_key, t2) == c2[idx: idx + len(t2)]:
            key = maybe_key
            offset = idx
            break
    else:
        raise ValueError, 'Could not get key'

    plain_dirt = ';admin=true'
    admin_data_middle = strxor('A' * (len(key) - len(plain_dirt)) + plain_dirt,
                               key)

    return c1[:offset] + admin_data_middle + c1[offset + len(admin_data_middle):]


def test_is_admin():
    server = mk_CTR_CookieSystem(BLOCK_SIZE)
    ciphertext = server.cipher.encrypt('admin=true;comment=bla')
    assert server.is_admin(ciphertext)


def test_mk_admin_data():
    server = mk_CTR_CookieSystem(BLOCK_SIZE)
    ciphertext = mk_admin_data(server.process_data)
    assert server.is_admin(ciphertext)
