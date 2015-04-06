
from random import randint
from Crypto.Cipher import AES

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
    num_trials = 1
    score = (sum(average_hamming(chunks(encryption_fn(test_strn), 16))
                for _ in xrange(num_trials))
             / float(num_trials) / 8.)

    if score < .4:
        #print 'ECB', score
        return AES.MODE_ECB
    else:
        #print 'CBC', score
        return AES.MODE_CBC


def try_encryption():
    strn = 'Hello, this is the plaintext!! Have a nice day.'
    ciphers = [rand_ECB_CBC() for _ in xrange(20)]
    ciphertexts = [c.encrypt(strn) for c in ciphers]
    print ciphertexts


def test_detection():
    ciphers = [rand_ECB_CBC() for _ in xrange(20)]

    encryption_fns = [c.encrypt for c in ciphers]

    modes = map(detect_ECB_or_CBC, encryption_fns)

    assert modes == [c.mode for c in ciphers]


if __name__ == '__main__':
    #try_encryption()
    test_detection()
