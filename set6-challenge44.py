import itertools
import binascii
import hashlib
import logging
import toolz as tz
import toolz.curried as tzc
import re
from collections import namedtuple

from Crypto.Util.number import long_to_bytes, bytes_to_long

import number_theory as nt
from my_dsa import (hash_fn, keygen, sign, verify,
                    p, q, g, get_privkey_from_k)


field_names = ['msg', 's', 'r', 'm']
MessageSet = namedtuple('MessageSet', field_names)


def message_set_to_signed_message(message_set):
    return (message_set.msg, (message_set.r, message_set.s))


def get_k_from_same_k_pair(message_set_1, message_set_2):
    """

        (m1 - m2)
    k = --------- mod q
        (s1 - s2)

    """

    m1, m2 = message_set_1.m, message_set_2.m
    s1, s2 = message_set_1.s, message_set_2.s

    try:
        k = nt.invmod(s1 - s2, q) * (m1 - m2) % q
        return True, k
    except nt.InvModException:
        return False, None


def maybe_get_privkey_from_pair(message_set_1, message_set_2):
    valid, maybe_k = get_k_from_same_k_pair(message_set_1, message_set_2)

    if not valid:
        return (False, None)

    maybe_r = nt.modexp(g, maybe_k, p) % q

    maybe_privkey_1 = get_privkey_from_k(
        message_set_to_signed_message(message_set_1), maybe_k)

    maybe_privkey_2 = get_privkey_from_k(
        message_set_to_signed_message(message_set_1), maybe_k)

    if maybe_privkey_1 == maybe_privkey_2:
        return (True, maybe_privkey_1)
    else:
        return (False, None)


def get_privkey_from_message_sets(pubkey, message_sets):
    for message_set_1, message_set_2 in itertools.combinations(message_sets, 2):
        valid, maybe_privkey = maybe_get_privkey_from_pair(message_set_1, message_set_2)

        if valid and nt.modexp(g, maybe_privkey, p) == pubkey:
            return maybe_privkey
    else:
        raise ValueError, 'no valid privkey found'


def _parse_field(field_name, txt):
    pattern = '{}: (.*)'.format(field_name)
    raw_data = re.search(pattern, txt).group(1)

    if field_name == 'msg':
        data = raw_data
    elif field_name in ('s', 'r'):
        data = long(raw_data, 10)
    elif field_name == 'm':
        data = long(raw_data, 16)

    return (field_name, data)


def parse_lines(lines):
    return [
        MessageSet(**dict(
            _parse_field(field_name, txt)
            for field_name, txt in zip(field_names, lines[ii:ii + 4])))
        for ii in xrange(0, len(lines), 4)
    ]


def test_get_privkey_from_message_sets():
    with open('challenge-data/44.txt', 'r') as fil:
        message_sets = parse_lines(fil.readlines())


    for message_set in message_sets:
        assert bytes_to_long(hash_fn(message_set.msg)) == message_set.m


    pubkey = long("""2d026f4bf30195ede3a088da85e398ef869611d0f68f07
                  13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
                  5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
                  f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
                  f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
                  2971c3de5084cce04a2e147821""".translate(None, ' \n'), 16)


    privkey = get_privkey_from_message_sets(pubkey, message_sets)

    assert (hashlib.sha1(binascii.hexlify(long_to_bytes(privkey))).hexdigest()
            == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')


if __name__ == '__main__':
    test_get_privkey_from_message_sets()
