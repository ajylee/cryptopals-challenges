import logging

import pkcs1
from my_rsa import keygen, encrypt, BLOCK_SIZE
from bleichenbacher import pkcs1_oracle, search


def recover_plaintext_test_tool(block_size):
    plaintext = "kick it, CC"
    padded = pkcs1.pad(plaintext, chr(2), block_size)

    pubkey, privkey = keygen(block_size)

    ciphertext = encrypt(pubkey, padded)

    _oracle = pkcs1_oracle(privkey, block_size)

    assert _oracle(ciphertext)

    recovered = search(
        _oracle, block_size, pubkey, ciphertext)

    assert recovered == padded, repr(recovered)

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
