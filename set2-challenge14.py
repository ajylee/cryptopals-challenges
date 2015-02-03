from Crypto.Cipher import AES
from block_crypto import random_str, pad, chunks, try_repeatedly, GaveUp
from random import randint
from toolz import frequencies

import set2_challenge12


block_size = 16

class rand_padded_ECB(object):
    """Random key, random left-padding"""

    def __init__(self):
        self.cipher = AES.new(key=random_str(block_size), mode=AES.MODE_ECB)
        self.target = random_str(130)

    def encrypt(self, data):
        processed = pad(random_str(randint(10, 100)) + data + self.target,
                        block_size=self.cipher.block_size)
        return self.cipher.encrypt(processed)



def strip_encrypt_fn(encrypt_fn, block_size):

    def _bare_stripped_encrypt_fn(data):
        nstim = 6
        stim_blocks = random_str(block_size) * nstim
        rand_block = random_str(randint(0, 16))

        ctxt = encrypt_fn(rand_block + stim_blocks + data)

        blocks = b = chunks(ctxt, size=block_size)

        for ii in xrange(len(blocks) - nstim + 1):
            if all(b[ii] == b[ii + jj] for jj in xrange(1, nstim)):
                return ''.join(b[ii + nstim:])

    def _stripped_encrypt_fn(data):
        return try_repeatedly(lambda : _bare_stripped_encrypt_fn(data),
                          max_tries=1000)

    return _stripped_encrypt_fn


def collect_bytes(encrypt_fn, keysize):
    # decrypt tail target string, assuming encrypt_fn has no pre-padding

    _target_string_len = len(encrypt_fn(''))

    _known = ''

    fails = 0
    while len(_known) < _target_string_len:
        try:
            next_byte = set2_challenge12.get_next_byte(
                encrypt_fn, keysize, _known)
            _known += next_byte
            fails = 0
            print repr(next_byte)
        except KeyError:
            fails += 1
            if fails > 10:
                raise GaveUp
            else:
                print '!' * 10 + 'fail (x{})'.format(fails)
                continue

    return _known


def solve_target(encrypt_fn, block_size):
    """Decrypt target using oracle"""
    stripped = strip_encrypt_fn(encrypt_fn, block_size)
    return collect_bytes(stripped, block_size)


def test_solve_target():
    cipher = rand_padded_ECB()
    solution = solve_target(cipher.encrypt, block_size=block_size)
    assert solution[:len(cipher.target)] == cipher.target


if __name__ == '__main__':
    test_solve_target()
