
import pkcs1
from my_rsa import keygen, encrypt, BLOCK_SIZE
from bleichenbacher import pkcs1_oracle

BLOCK_SIZE = 256

def recover_plaintext(oracle, pubkey, ciphertext):
    pass


def test_recover_plaintext():
    plaintext =  "kick it, CC"

    pubkey, privkey = keygen(BLOCK_SIZE)

    ciphertext = encrypt(pubkey, pkcs1.pad(plaintext))

    _oracle = pkcs1_oracle(privkey)

    assert recover_plaintext(_oracle, pubkey, ciphertext) == plaintext
