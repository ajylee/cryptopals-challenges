import binascii
import hashlib
import logging
import toolz as tz
import re
from collections import namedtuple

from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_dsa import (hash_fn, keygen, sign_plus, sign, verify,
                    p, q, g)


field_names = ['msg', 's', 'r', 'm']
SignatureSet = namedtuple('SignatureSet', field_names)


def get_k_from_signed_messages(signed_message_1, signed_message_2):
    """

        (m1 - m2)
    k = --------- mod q
        (s1 - s2)

    """
    signed_messages = signed_message_1, signed_message_2

    m1, m2 = tz.map(bytes_to_long, tz.pluck(0, signed_messages))
    s1, s2 = tz.pluck((1, 1), signed_messages)

    k = nt.invmod(s1 - s2, q) * (m1 - m2) % q

    return k


def _parse_field(field_name, txt):
    pattern = '{}: (.*)'.format(field_name)
    raw_data = re.search(pattern, txt).group(1)

    if field_name == 'msg':
        return raw_data
    elif field_name in ('s', 'r'):
        return long(data, 10)
    elif field_name == 'm':
        return long(data, 16)


def parse_lines(lines):
    return [
        SignatureSet(*(_parse_field(field_name, txt)
                       for field_name, txt in zip(field_names, lines[ii:ii + 4])))
        for ii in xrange(0, len(lines), 4)
    ]


def test():
    with open('challenge-data/44.txt', 'r') as fil:
        sigsets = parse_lines(fil.readlines())

    print sigsets


    pubkey = long("""2d026f4bf30195ede3a088da85e398ef869611d0f68f07
                  13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
                  5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
                  f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
                  f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
                  2971c3de5084cce04a2e147821""".translate(None, ' \n'), 16)


    assert (hashlib.sha1(binascii.hexlify(long_to_bytes(privkey))).hexdigest()
            == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')



if __name__ == '__main__':
    test()
