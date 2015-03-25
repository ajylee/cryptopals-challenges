from __future__ import division
import Crypto.Random
from block_crypto import CTR, strxor
from bin_more import ords as str_to_ords

BLOCK_SIZE = 16


class EncryptedEditor(object):
    def __init__(self):
        rand_io = Crypto.Random.new()
        key = rand_io.read(BLOCK_SIZE)
        nonce = str_to_ords(rand_io.read(BLOCK_SIZE // 2))

        self.cipher = CTR(key, nonce)

    def encrypt(self, plaintext):
        return self.cipher.encrypt(plaintext)

    def decrypt(self, plaintext):
        return self.encrypt(plaintext)

    def edit(self, ciphertext, offset, new_text):
        plaintext = self.cipher.decrypt(ciphertext)
        new_plaintext = (plaintext[:offset]
                         + new_text
                         + plaintext[offset + len(new_text):])
        return self.encrypt(new_plaintext)


def test_edit():
    ee = EncryptedEditor()
    plaintext = 'this is the original plaintext'
    ciphertext = ee.encrypt(plaintext)

    offset = len('this is the ')
    edited = ee.edit(ciphertext, offset, 'edited  ')
    assert ee.decrypt(edited) == 'this is the edited   plaintext'


def solve_plaintext(edit_method, ciphertext):
    new_text = 'A' * len(ciphertext)
    keystream = strxor(edit_method(ciphertext, 0, new_text),
                       new_text)

    return strxor(keystream, ciphertext)


def test_solve_plaintext():
    ee = EncryptedEditor()
    plaintext = 'this is the secret message. Secret! Secret!'
    ciphertext = ee.encrypt(plaintext)
    assert solve_plaintext(ee.edit, ciphertext) == plaintext


if __name__ == '__main__':
    test_edit()
    test_solve_plaintext()
