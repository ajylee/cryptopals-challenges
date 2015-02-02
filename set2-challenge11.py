
from random import randint
from Cytpo.Cipher import AES
from block_crypto import CBC, random_str


class rand_ECB_CBC(object):
    def __init__(self):
        key = random_str(16)

        if randint(0,1):
            self.cipher = AES.new(key, AES.MODE_ECB)
        else:
            iv = random_str(16)
            self.cipher = CBC(key, iv)

    def encrypt(self, strn):
        random_pad = lambda : random_str(randint(5, 10))
        padded = random_pad() + strn + random_pad()
        return self.cipher.encrypt(padded)
