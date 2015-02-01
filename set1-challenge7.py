
import toolz as tz

import base64
from Crypto.Cipher import AES
from Crypto import Random
from set1_challenge3 import printable


def pad(cipher, strn):
    return strn + ' ' * (-len(strn) % cipher.block_size)


def test_cipher():
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)

    test_msg = pad(cipher, b'Attack at dawn')
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
