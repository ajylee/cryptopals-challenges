
import binascii
from set1_challenge3 import top_ciphered, score


def solve():
    with open('4.txt','r') as fil:
        for num, line in enumerate(fil.readlines()):

            _l = binascii.unhexlify(line.strip())
            for key, ss, _score in top_ciphered(_l, limit=3):
                if _score > 27:
                    print num, _score, repr(ss)

print solve()
