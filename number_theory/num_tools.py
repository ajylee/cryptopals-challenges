
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


def invmod(a, n):
    # adapted from haskell and python versions in Rosetta Code
    g, x, y = extended_gcd(a, n)
    if g != 1:
        print 'g != 1'
    return x % n


def test_invmod():
    assert invmod(17, 3120) == 2753
    assert invmod(3, 11) == 4
    assert invmod(42, 2017) == 1969
