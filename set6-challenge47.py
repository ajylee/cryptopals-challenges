import logging

import pkcs1
from my_rsa import keygen, encrypt, BLOCK_SIZE
from bleichenbacher import pkcs1_oracle, search

BLOCK_SIZE = 256 // 8


def test_recover_plaintext():
    plaintext =  "kick it, CC"

    pubkey, privkey = keygen(BLOCK_SIZE)

    ciphertext = encrypt(pubkey, pkcs1.pad(plaintext, BLOCK_SIZE))

    _oracle = pkcs1_oracle(privkey)

    assert search(_oracle, BLOCK_SIZE, pubkey, ciphertext) == plaintext


if __name__ == '__main__':
    import bleichenbacher
    logging.basicConfig()
    bleichenbacher.logger.setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)

    test_recover_plaintext()
