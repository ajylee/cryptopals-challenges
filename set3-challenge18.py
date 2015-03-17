
import base64
import random
import Crypto.Random 
from block_crypto import CTR
from Crypto.Cipher import AES
import logging

BLOCK_SIZE = 16

def test_CTR():
    nonce = random.randint(0, 2**(8 * BLOCK_SIZE // 2 - 1))
    key = Crypto.Random.new().read(BLOCK_SIZE)
    cipher = CTR(key=key, nonce=nonce)

    for ii in xrange(10):
        random_str = Crypto.Random.new()
        rand_test_str = random_str.read(60)
        assert cipher.decrypt(cipher.encrypt(rand_test_str)) == rand_test_str

def decrypt_message():
    test_str = ( r'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY'
                 r'/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==' )
    nonce = 0
    key = 'YELLOW SUBMARINE'

    cipher = CTR(key=key, nonce=nonce)

    print repr(cipher.decrypt(base64.b64decode(test_str)))


if __name__ == '__main__':
    import block_crypto

    logging.basicConfig()
    logging.getLogger(block_crypto.__name__).setLevel(logging.CRITICAL)
    test_CTR()
    logging.getLogger(block_crypto.__name__).setLevel(logging.DEBUG)
    decrypt_message()
