
import toolz as tz
import base64
import os.path as osp

from block_crypto import CBC
from set1_challenge6 import chunks


def test_cipher():
    strn = 'hello ' * 20
    key = b'YELLOW SUBMARINE'
    iv = chr(0) * len(key)

    c = CBC(key, iv)
    enc = c.encrypt(strn)
    print repr(enc)
    assert c.decrypt(enc).startswith(strn)


def solve():
    with open('challenge-data/10.txt') as f:
        strn = base64.b64decode(f.read())

    key = b'YELLOW SUBMARINE'
    iv = chr(0) * len(key)

    for line in CBC(key, iv).decrypt(strn).split('\n'):
        print repr(line)


if __name__ == '__main__':
    test_cipher()
    solve()
