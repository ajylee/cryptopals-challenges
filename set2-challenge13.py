
import re
import string
import random
from collections import OrderedDict, Counter

from toolz import valmap, identity, get, take, tail, compose
import pyparsing as pp
from pyparsing import (Word, alphas, alphanums, Forward, ZeroOrMore, Literal,
                       Group, delimitedList, SkipTo)
from Crypto.Cipher import AES

from block_crypto import random_str, pad, chunks, try_repeatedly


def last_block(strn):
    return strn[-16:]

def second_block(strn):
    return strn[16:32]

str_take = compose(''.join, take)
str_tail = compose(''.join, tail)


class KEV(object):
    key = Word(alphas).setResultsName('key')
    value = Word(alphanums + '@.').setResultsName('value')
    kv_pair = Group(key + '=' + value)
    dict_bnf = delimitedList(kv_pair, delim='&')

    @classmethod
    def decode(cls, strn):
        results = cls.dict_bnf.parseString(strn)
        return {rr.key : rr.value for rr in results}

    @classmethod
    def encode(cls, dict_):
        return '&'.join('{}={}'.format(k,v) for k,v in dict_.items())


class Profile(object):
    control_chars = '&='

    # Screening nonprintable too strong?
    # invalid = [ii for ii in xrange(33)] + [ord(c) for c in control_chars]
    invalid = [ord(c) for c in control_chars]
    delete_table = {o:None for o in invalid}
    keys = ['email', 'uid', 'role']

    @classmethod
    def remove_invalid(cls, strn):
        return unicode(strn).translate(cls.delete_table)

    @classmethod
    def encode(cls, dict_):
        #valid = [
        #    (SkipTo(KEV.key, include=True).parseString(k)[0].key,
        #     SkipTo(KEV.value, include=True).parseString(str(dict_[k]))[0].value)
        #    for k in cls.keys
        #]

        return KEV.encode(OrderedDict((k, dict_[k]) for k in cls.keys))

    @classmethod
    def finalize(cls, tainted_data):
        _finalize = {'email': cls.remove_invalid,
                     'uid': int,
                     'role': cls.remove_invalid}

        return {k: _finalize[k](tainted_data[k]) for k in cls.keys}

    @classmethod
    def decode(cls, strn):
        return cls.finalize(KEV.decode(strn))


class ProfileManager(object):
    def __init__(self):
        self.profiles = {}
        self.uids = {0}
        self.cipher = AES.new(random_str(16), AES.MODE_ECB)
        self.pad_str = chr(4)

    def unsafe_get_profile_for(self, email):
        _maybe_profile = self.profiles.get(email, None)
        if _maybe_profile:
            return _maybe_profile
        else:
            return None

    def profile_for(self, email):
        valid_email = Profile.remove_invalid(email)
        del email

        maybe_profile = self.unsafe_get_profile_for(valid_email)

        if maybe_profile:
            profile = maybe_profile
        else:
            profile = {'email': valid_email,
                       'uid': max(self.uids) + 1,
                       'role': 'user'}

            self.unsafe_add_profile(**profile)

        return self.cipher.encrypt(pad(Profile.encode(profile),
                                block_size=self.cipher.block_size,
                                pad_str=self.pad_str))

    def read_cookie(self, cookie):
        decrypted = self.cipher.decrypt(cookie)
        stripped = decrypted.rstrip(self.pad_str)
        return Profile.decode(stripped)

    def unsafe_add_profile(self, email, uid, role):
        self.uids.add(uid)
        self.profiles[email] = dict(email=email,
                                 uid=uid,
                                 role=role)


class Test(object):
    dec_tests = [
        ('foo=bar&baz=qux&zap=zazzle',
         {'foo': 'bar',
          'baz': 'qux',
          'zap': 'zazzle'})]

    profile_tests = [
        ('email=joe@bob.com&uid=99&role=user',
         {'email': 'joe@bob.com',
          'uid': 99,
          'role': 'user'})
    ]

    @classmethod
    def test_kev_decoder(cls):
        for enc, dec in cls.dec_tests:
            assert KEV.decode(enc) == dec

    @classmethod
    def test_profile_codec(cls):
        for enc, dec in cls.profile_tests:
            assert Profile.encode(dec) == enc


# Attack
# -------

DOMAIN = '@example.org'


def random_username(length):
    return ''.join(string.ascii_lowercase[random.randint(0,25)]
               for ii in xrange(length))


def mk_role_user_reverse_lookup(profile_for):
    common_pads = [' ', chr(4), chr(8)]

    usernames = [pad('user', block_size=16, pad_str=pad_str)
               for pad_str in common_pads]

    first_block = lambda : random_username(16 - len('email='))

    return {profile_for(first_block() + username + DOMAIN)[16:32]: username[-1]
        for username in usernames}


def get_base_cookie(profile_for, role_user_reverse_lookup):
    """Get a username length such that the last block has only one content byte"""
    for ii in xrange(5, 16 + 5):
        username = random_username(ii)
        cookie = profile_for(username + DOMAIN)
        last_block = str_tail(16, cookie)
        if repr(last_block) in map(repr, role_user_reverse_lookup.keys()):
            return cookie, role_user_reverse_lookup[last_block]


def mk_admin_cookie(profile_for):
    role_user_reverse_lookup = mk_role_user_reverse_lookup(profile_for)

    thunk = lambda : get_base_cookie(profile_for, role_user_reverse_lookup)
    base_cookie, pad_str = try_repeatedly(thunk, max_tries=1)

    admin_block = second_block(
        profile_for(
            random_username(16 - len('email='))
            + pad('admin', block_size=16, pad_str=pad_str)))

    admin_cookie = base_cookie[:-16] + admin_block

    return admin_cookie


def test_mk_admin_cookie():
    pman = ProfileManager()
    cookie = mk_admin_cookie(pman.profile_for)
    assert pman.read_cookie(cookie)['role'] == 'admin'


# Testing
# --------

def test_naive_attack_email():
    # Test that naive attack fails
    legit_email = 'abc@example.com'
    attack_email = legit_email + '&uid=10&role=admin'
    valid_email = Profile.remove_invalid(attack_email)

    for control_char in Profile.control_chars:
        assert control_char not in valid_email

    pman = ProfileManager()

    # add legit admin user
    pman.profile_for(email=legit_email)
    pman.profiles[legit_email]['role'] = 'admin'

    attack_cookie = pman.profile_for(email=attack_email)
    attack_profile = pman.read_cookie(attack_cookie)
    decrypted_cookie = pman.cipher.decrypt(attack_cookie)
    assert attack_profile['role'] == 'user'
    assert re.search('=user', decrypted_cookie)
    assert not re.search('=admin', decrypted_cookie)


if __name__ == '__main__':
    Test.test_kev_decoder()
    Test.test_profile_codec()

    #r = SkipTo(KEV.key, include=True).parseString('@abc')
    test_naive_attack_email()

    test_mk_admin_cookie()
    #profile_for('abc@example.com&uid=10&role=user')
