
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


