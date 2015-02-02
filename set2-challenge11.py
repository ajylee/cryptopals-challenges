
from random import randint
from Crypto.Cipher import AES

import gen
from block_crypto import CBC, random_str, pad, chunks

from set1_challenge6 import average_hamming


class rand_ECB_CBC(object):
    def __init__(self):
        self.block_size = 16
        key = random_str(self.block_size)

        if randint(0,1):
            self.mode = AES.MODE_ECB
            self.cipher = AES.new(key, AES.MODE_ECB)
        else:
            iv = random_str(self.block_size)
            self.mode = AES.MODE_CBC
            self.cipher = CBC(key, iv)

    def encrypt(self, strn):
        random_pad = lambda : random_str(randint(5, 10))
        padded = pad(random_pad() + strn + random_pad(),
                     block_size=self.block_size)
        return self.cipher.encrypt(padded)

    def decrypt(self, strn):
        return self.cipher.decrypt(strn) # does not take padding into account


def detect_ECB_or_CBC(encryption_fn):
    test_strn = 'a' * 128
    num_trials = 10
    score = (sum(average_hamming(chunks(encryption_fn(test_strn), 16))
                for _ in xrange(num_trials))
             / float(num_trials) / 8.)

    if score < .45:
        return AES.MODE_ECB
    else:
        return AES.MODE_CBC


def test_detection():
    ciphers = [rand_ECB_CBC() for _ in xrange(20)]

    encryption_fns = [c.encrypt for c in ciphers]

    modes = map(detect_ECB_or_CBC, encryption_fns)

    assert modes == [c.mode for c in ciphers]


if __name__ == '__main__':
    test_detection()
