
from toolz import valmap, identity
from collections import OrderedDict
import pyparsing as pp
from pyparsing import (Word, alphas, alphanums, Forward, ZeroOrMore, Literal, Group,
                       delimitedList, SkipTo)

import string


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
    invalid = [ii for ii in xrange(33)] + [ord(c) for c in control_chars]
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
    def mk_valid(cls, tainted_data):
        finalize = {'email': cls.remove_invalid,
                    'uid': int,
                    'role': cls.remove_invalid}

        return {k: finalize[k](tainted_data) for k in cls.keys}

    @classmethod
    def decode(cls, strn):
        return mk_valid(KEV.encode(strn))


class ProfileManager(object):
    def __init__(self):
        self.profiles = {}
        self.uids = set()

    def unsafe_profile_for(self, email):
        _maybe_profile = self.profiles.get(email, None)
        if _maybe_profile:
            return Profile.encode(_maybe_profile)
        else:
            return None

    def profile_for(self, email_strn):
        valid_email = Profile.remove_invalid(email_strn)
        return self.unsafe_profile_for(valid_email)

    def unsafe_add_profile(self, email, uid, role):
        self.profiles[email] = dict(email=email,
                                 uid=uid,
                                 role=role)

    def add_profile(self, email, uid, role):
        assert isinstance(uid, int)
        self.unsafe_add_profile(
            email = Profile.remove_invalid(email),
            uid = uid,
            role = Profile.remove_invalid(role))


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


def test_attack_email():
    legit_email = 'abc@example.com'
    attack_email = legit_email + '&uid=10&role=admin'
    valid_email = Profile.remove_invalid(attack_email)

    for control_char in Profile.control_chars:
        assert control_char not in valid_email

    pman = ProfileManager()

    # add legit user
    pman.add_profile(email=legit_email, uid=10, role='admin')
    pman.unsafe_add_profile(email=attack_email, uid=11, role='user')
    assert pman.unsafe_profile_for(attack_email).startswith(
        pman.profile_for(legit_email))
    assert pman.profile_for(attack_email) is None


if __name__ == '__main__':
    Test.test_kev_decoder()
    Test.test_profile_codec()

    #r = SkipTo(KEV.key, include=True).parseString('@abc')
    test_attack_email()

    #profile_for('abc@example.com&uid=10&role=user')
