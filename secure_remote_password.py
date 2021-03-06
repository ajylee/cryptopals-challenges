from collections import namedtuple
import binascii
import random
import contextlib
from hashlib import sha256
from hmac import HMAC

import number_theory.diffie_hellman as dh
import number_theory as nt


LoginData = namedtuple('LoginData', [
    'N', 'g', 'k', 'email', 'password'])

SessionData = namedtuple('SessionData', [
    'salt', 'K'])


def mk_login_data(email, password):
    return LoginData(
        N = long(dh.NIST_P_HEX, 16),
        g = 2,
        k = 3,
        email = email,
        password = password,)


PUBLIC_LOGIN_DATA = mk_login_data(None, None)

CLIENT_LOGIN_DATA = mk_login_data(email = 'abc@example.org',
                                  password = 'some_password',)


def int_to_str(nn):
    hex_rep = hex(nn)[2:].rstrip('L')
    padded = '0' * (len(hex_rep) % 2) + hex_rep
    return binascii.unhexlify(padded)

def str_to_int(ss):
    return long(binascii.hexlify(ss), 16)


def gen_salt():
    return random.randint(0, 0xffffffff)


def calculate_u(A, B):
    uH = sha256(int_to_str(A + B)).digest()
    return str_to_int(uH)


def calculate_x(salt, password):
    xH = sha256(int_to_str(salt) + password).digest()
    return str_to_int(xH)


def calculate_K_client(B, k, g, x, a, u, N):
    # S = (B - k * g**x)**(a + u * x) % N
    S = nt.modexp(B - k * nt.modexp(g, x, N), (a + u * x), N)
    K = sha256(int_to_str(S)).digest()
    return K


def calculate_K_server(A, v, u, b, N):
    #  S = (A * v**u) ** b % N
    S = nt.modexp(A * nt.modexp(v, u, N), b, N)
    K = sha256(int_to_str(S)).digest()
    return K


def gen_bB_server(login_data, v):
    dat = login_data
    b = dh.mod_random(dat.N)
    B = dat.k * v + nt.modexp(dat.g, b, dat.N)
    return b, B


def gen_salt_and_v_server(login_data):
    dat = login_data
    salt = gen_salt()
    x = calculate_x(salt, dat.password)
    v = nt.modexp(dat.g, x, dat.N)
    return salt, v


def simple_private_public_pair(g, N):
    priv = dh.mod_random(N)
    pub = nt.modexp(g, priv, N)
    return priv, pub


class Server(object):
    def __init__(self):
        self.login_data = {CLIENT_LOGIN_DATA.email: CLIENT_LOGIN_DATA}
        self.session_data = {}
        self._session_count = 0

    def new_session(self):
        _id = self._session_count
        self._session_count += 1
        self.session_data[_id] = {}
        return _id

    def respond_handshake(self):
        session_id = self.new_session()

        email = yield

        dat = self.login_data[email]
        salt, v = gen_salt_and_v_server(dat)

        A = yield

        b, B = gen_bB_server(dat, v)

        u = calculate_u(A, B)
        K = calculate_K_server(A, v, u, b, dat.N)

        self.session_data[session_id] = SessionData(salt, K)

        client_hmac = yield (salt, B)
        my_hmac = HMAC(K, int_to_str(salt)).hexdigest()

        if my_hmac == client_hmac:
            yield 'OK'
        else:
            yield 'INVALID HMAC'


class Client(object):
    def __init__(self):
        self.my_login_data = CLIENT_LOGIN_DATA
        self.handshake_data = None

    def conduct_handshake(self, response_delegate):
        dat = self.my_login_data

        response_delegate.next()
        response_delegate.send(dat.email)

        a, A = simple_private_public_pair(dat.g, dat.N)

        salt, B = response_delegate.send(A)

        u = calculate_u(A, B)
        x = calculate_x(salt, self.my_login_data.password)
        K = calculate_K_client(B, dat.k, dat.g, x, a, u, dat.N)

        self.handshake_data = SessionData(salt, K)

        hmac = HMAC(K, int_to_str(salt)).hexdigest()
        validation_message = response_delegate.send(hmac)
        assert validation_message == 'OK'

        response_delegate.close()


def test_SRP():
    s = Server()
    c = Client()
    with contextlib.closing(s.respond_handshake()) as rd:
        c.conduct_handshake(rd)


if __name__ == '__main__':
    test_SRP()
