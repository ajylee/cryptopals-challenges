
import binascii
from set1_challenge3 import top_ciphered, score


def solve():
    with open('4.txt','r') as fil:
        for num, line in enumerate(fil.readlines()):

            _l = binascii.unhexlify(line.strip())
            for ss in top_ciphered(_l, limit=3):
                if score(ss) > 27:
                    print num, score(ss), repr(ss)

print solve()
