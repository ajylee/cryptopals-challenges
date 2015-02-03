import base64

from random import randint
from Crypto.Cipher import AES

import gen
from block_crypto import CBC, random_str, pad, chunks

from set1_challenge6 import hamming, average_hamming


unknown_string = (
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    'YnkK')


class rand_ECB(object):
    def __init__(self):
        self.block_size = 16
        key = random_str(self.block_size)
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, strn):
        padded = pad(strn + base64.b64decode(unknown_string),
                     block_size=self.block_size)
        return self.cipher.encrypt(padded)

    def decrypt(self, strn):
        return self.cipher.decrypt(strn) # does not take padding into account


def step_1(encrypt_fn):
    # feed identical bytes, determine keysize

    _byte = 'A'

    curr_len = start_len = len(encrypt_fn('A'))

    for ii in xrange(2, 100):
        curr_len = len(encrypt_fn(_byte * ii))
        if curr_len != start_len:
            return curr_len - start_len


def step_2(encrypt_fn, keysize):
    # detect ECB

    _byte = 'A'
    encrypted = encrypt_fn(_byte * keysize * 10)
    nchunks = len(encrypted) // keysize
    _score = average_hamming(chunks(encrypted, keysize, nchunks)) / 8.

    return _score < .45


def step_3(encrypt_fn, keysize):
    # decrypt unknown_string

    _target_string_len = len(encrypt_fn(''))

    def get_next_byte(known):
        lpad_len = (-len(known) - 1) % keysize
        lpad = 'A' * lpad_len

        entry_len = len(known) + lpad_len + 1

        _inputs = (lpad + known + _c for _c in gen.chars)
        _reverse_lookup = {encrypt_fn(_input)[:entry_len]: _input
                           for _input in _inputs}

        _with_unknown_byte = encrypt_fn(lpad)[:entry_len]

        return _reverse_lookup[_with_unknown_byte][-1]


    _known = ''

    while len(_known) < _target_string_len:
        _known += get_next_byte(_known)

    return _known



if __name__ == '__main__':
    cipher = rand_ECB()
    keysize = step_1(cipher.encrypt)
    print 'Keysize:', keysize

    is_ECB = step_2(cipher.encrypt, keysize)
    print 'Uses ECB:', is_ECB

    msg = step_3(cipher.encrypt, keysize)

    print 'Message:'
    print '-' * 50

    for line in msg.split('\n'):
        print repr(line)
