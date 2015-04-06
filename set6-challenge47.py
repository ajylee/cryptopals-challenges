import logging

import pkcs1
from my_rsa import keygen, encrypt, BLOCK_SIZE
from bleichenbacher import pkcs1_oracle, search
from memo import memo


def recover_plaintext_test_tool(block_size):
    plaintext =  "kick it, CC"

    pubkey, privkey = memo(__name__ + '.keygen', lambda : keygen(block_size))

    ciphertext = encrypt(pubkey, pkcs1.pad(plaintext, chr(2), block_size))

    _oracle = pkcs1_oracle(privkey, block_size)

    assert _oracle(ciphertext)

    ok_padding, solution = pkcs1.check_and_remove_padding(
        search(_oracle, block_size, pubkey, ciphertext),
        chr(2))

    
    assert solution == plaintext, solution

    logging.info('solution matches plaintext')


def test_recover_plaintext_47():
    recover_plaintext_test_tool(256 // 8)


def test_recover_plaintext_48():
    recover_plaintext_test_tool(768 // 8)


if __name__ == '__main__':
    import bleichenbacher
    logging.basicConfig()
    bleichenbacher.logger.setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)

    test_recover_plaintext_47()
    test_recover_plaintext_48()
