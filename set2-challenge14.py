from Crypto.Cipher import AES
from block_crypto import random_str, pad, chunks
from random import randint
from toolz import frequencies

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


        
def strip(encrypt_fn, block_size):

    def _stripped_encrypt_fn(data):
        stim_block = random_str(block_size) + random_str(block_size)
        rand_block = random_str(randint(0, 16))

        ctxt = encrypt_fn(rand_block + stim_block + data)

        blocks = b = chunks(ctxt, size=block_size)
        for ii in xrange(len(blocks) - 3):
            if (b[ii] == b[ii + 2]
                and b[ii + 1] == b[ii + 3]):
                return ''.join(b[ii + 4:])


    return _stripped_encrypt_fn


def solve_target(encrypt_fn, block_size):
    """Decrypt target using oracle"""

    stripped = strip(encrypt_fn, block_size)



    


def test_solve_target():
    cipher = rand_padded_ECB()
    solution = solve_target(cipher.encrypt, block_size=block_size)
    #assert solution == cipher.target


if __name__ == '__main__':
    test_solve_target()
    
        

