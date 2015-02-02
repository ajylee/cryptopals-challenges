
import base64
import os.path as osp
from random import randint
from Crypto.Cipher import AES

import gen
from block_crypto import CBC, random_str, pad


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
    test_strn = 'a' * 16 + 'b' * 16
    encryption_fn(test_strn)


def test_detection():
    #with open(osp.join(gen.datadir, '10.txt')) as f:
    #    strn = base64.b64decode(f.read())

    ciphers = [rand_ECB_CBC() for _ in xrange(10)]

    ciphertexts = [c.encrypt(strn) for c in ciphers]

    print ciphertexts


if __name__ == '__main__':
    test_detection()
