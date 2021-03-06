
def long_xrange(initial_or_upper_bound, maybe_upper_bound=None, step=1):
    """Like xrange but takes longs"""

    if maybe_upper_bound is None:
        initial, upper_bound = 0, initial_or_upper_bound
    else:
        initial, upper_bound = initial_or_upper_bound, maybe_upper_bound

    for ii in count(initial, step):
        if ii < upper_bound:
            yield ii
        else:
            break


def long_root(nn, rr):
    _float_root = nn ** (1./float(rr))
    _guess = long(round(_float_root))
    change = long(round(_guess ** (1. / float(rr))))

    while True:
        _maybe_nn = _guess ** rr

        if _maybe_nn == nn:
            return _guess
        else:
            diff = nn - _maybe_nn
            assert diff > 0

            change = max(long(round(diff / float((2 ** rr - 1) * _guess ** 2))),
                         1)

            _guess += change


def ceil_div(nn, dd):
    div, mod = divmod(nn, dd)
    return div + int(mod != 0)


def byte_count(n):
    count = 0
    while n:
        n >>= 8
        count += 1
    return count


def modexp(g, u, p):
    """computes s = (g ^ u) mod p
    args are base, exponent, modulus
    (see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
    s = 1
    while u != 0:
        if u & 1:
            s = (s * g)%p
        u >>= 1
        g = (g * g)%p;
    return s


def _sgn(nn):
    return (-1 if nn < 0 else 1)



def _next_ab(a, b):
    # rem: [a, b, a % b, b % (a % b), a % b % (b % (a % b)), ...]
    # div: [_, _, a / b, b / (a % b), a % b / (b % (a % b)), ...]
    div, next_b = divmod(a, b)
    return (b, a % b, a // b)

def _next_xy(x0, x1, div):
    # x: [1, 0,       1,             -div[3], 1 + div[3] * div[4], ...]
    # y: [0, 1, -div[2], 1 + div[2] * div[3],
    #     -div[2] - div[4] - div[2] * div[3] * div[4], ...]
    x2 = x0 - div * x1
    return x2


def extended_gcd(aa, bb):
    # adapted from haskell and python versions in Rosetta Code
    # extended euclidian algorithm

    last_remainder, remainder = abs(aa), abs(bb)
    last_x, x = 1, 0
    last_y, y = 0, 1

    while remainder:
        last_remainder, remainder, div = _next_ab(last_remainder, remainder)
        x, last_x = _next_xy(last_x, x, div), x
        y, last_y = _next_xy(last_y, y, div), y

    return (last_remainder, last_x * _sgn(aa), last_y * _sgn(bb))


class InvModException(Exception):
    pass


def invmod(a, n):
    # adapted from haskell and python versions in Rosetta Code
    g, x, y = extended_gcd(a, n)

    if g != 1:
        raise InvModException

    return x % n


def test_invmod():
    assert invmod(17, 3120) == 2753
    assert invmod(3, 11) == 4
    assert invmod(42, 2017) == 1969
