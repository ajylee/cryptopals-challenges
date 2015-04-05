

def chrs(nn):
    ans = ''

    while nn:
        ans += chr(nn & (2**8 - 1))
        nn >>= 8

    return ans


def ords(ss):
    ans = 0

    while ss:
        ans <<= 8
        ans |= ord(ss[-1])
        ss = ss[:-1]

    return ans


def bit_count(ii):
    _cnt = 0

    while ii > 0:
        _cnt += ii & 1
        ii >>= 1

    return _cnt


def num_bits(ii):
    _cnt = 0
    
    while ii:
        ii >>= 1
        _cnt += 1

    return _cnt


def test_chrs_ords():
    for nn in range(10000):
        assert nn == ords(chrs(nn))

    for ss in ['abxtasoe', '35saetx.^$']:
        assert ss == chrs(ords(ss))
