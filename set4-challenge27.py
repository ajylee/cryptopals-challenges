from functools import partial
import Crypto.Random
from block_crypto import CBC, strxor, chunks

BLOCK_SIZE = 16

def solve_key(compliance_fn, ciphertext):

    c = chunks(ciphertext, BLOCK_SIZE)

    edited = c[0] + BLOCK_SIZE * chr(0) + c[0] + ''.join(c[3:])

    pp = chunks(compliance_fn(edited), BLOCK_SIZE)
    assert pp != None

    return strxor(pp[0], pp[2])


def high_byte(n):
    return n >= 127


def complies_ascii(cipher, ciphertext):
    """Simulate receiver ascii compliance test

    Returns plaintext on failure

    """
    pt = cipher.decrypt(ciphertext)
    if any(high_byte(bb) for bb in pt):
        return pt
    else:
        return None


def test_solve_key():
    rand_io = Crypto.Random.new()
    key = rand_io.read(BLOCK_SIZE)
    cipher = CBC(key, key, encipher_iv=False)
    compliance_fn = partial(complies_ascii, cipher)

    plaintext = rand_io.read(BLOCK_SIZE * 10)
    ciphertext = cipher.encrypt(plaintext)

    solved_key = solve_key(compliance_fn, ciphertext)

    assert solved_key == key
