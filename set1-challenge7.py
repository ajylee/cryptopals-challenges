
import toolz as tz

import base64
from Crypto.Cipher import AES
from Crypto import Random
from set1_challenge3 import printable
from block_crypto import pad


def test_cipher():
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)

    test_msg = pad(b'Attack at dawn', cipher.block_size)
    encrypted = cipher.encrypt(test_msg)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_msg


def solve():
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)

    with open('7.txt') as fil:
        ss = base64.b64decode(fil.read())

        decrypted = cipher.decrypt(ss)

        print filter(printable, decrypted)


if __name__ == '__main__':
    test_cipher()
    solve()
