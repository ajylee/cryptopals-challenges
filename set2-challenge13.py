
import pyparsing as pp
from pyparsing import Word, alphas, Forward, ZeroOrMore, Literal, Group

class KEV(object):
    kev_pair = Group((Word(alphas).setResultsName('k')
                      + '='
                      + Word(alphas).setResultsName('v')))

    kev_dict = Forward()
    kev_dict << kev_pair + ZeroOrMore(Literal('&').suppress() + kev_pair)

    @classmethod
    def parse(cls, strn):
        results = cls.kev_dict.parseString(strn)

        return {rr.k : rr.v
            for rr in results}


def test_kev_parser():
    test_inp = 'foo=bar&baz=qux&zap=zazzle'
    desired_out = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle'
    }

    assert KEV.parse(test_inp) == desired_out


if __name__ == '__main__':
    parsed = test_kev_parser()
