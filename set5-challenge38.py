
import os
import contextlib
import binascii
import time
from hashlib import sha256
from hmac import HMAC
import threading
import logging
import string
import itertools

import secure_remote_password as srp
import socket_handshake
import number_theory as nt


LEGIT_ADDRESS = ('localhost', 8081)
MITM_ADDRESS = ('localhost', 9081)


def calculate_simp_K_client(B, a, u, x, N):
    # S = B**(a + ux) % n
    S = nt.modexp(B, (a + u * x), N)
    K = sha256(srp.int_to_str(S)).digest()
    return K


def gen_u():
    return srp.str_to_int(os.urandom(16))


def mk_hmac_oracle(g, N, A, salt, b, u, hmac):
    unhexlified_hmac = binascii.unhexlify(hmac)

    def _hmac_oracle(password):
        x = srp.calculate_x(salt, password)
        v = nt.modexp(g, x, N)
        K = srp.calculate_K_server(A, v, u, b, N)
        return HMAC(K, srp.int_to_str(salt)).digest() == unhexlified_hmac

    return _hmac_oracle


def gen_guesses():
    words = ('a', 'the', 'some', 'pass', 'password', 'word', 'hahaha')
    separators = ('', ' ', '_')
    possible_lengths = range(4)
    count = 0
    count_limit = 1000

    for ll in possible_lengths:
        for ss in itertools.product(words, repeat=ll):
            for separator in separators:
                if count > count_limit:
                    raise StopIteration
                else:
                    count += 1
                    curr_guess = separator.join(ss)
                    logging.info('Guessing password: {}'.format(curr_guess))
                    yield curr_guess


def solve_password(oracle):
    for guess in gen_guesses():
        if oracle(guess):
            return guess


class SimplifiedServer(object):
    login_data = {srp.CLIENT_LOGIN_DATA.email: srp.CLIENT_LOGIN_DATA}

    def respond_handshake(self):
        email, A = yield

        dat = self.login_data[email]

        salt, v = srp.gen_salt_and_v_server(dat)

        b, B = srp.simple_private_public_pair(dat.g, dat.N)
        u = gen_u()

        K = srp.calculate_K_server(A, v, u, b, dat.N)

        client_hmac = yield salt, B, u

        if HMAC(K, srp.int_to_str(salt)).hexdigest() == client_hmac:
            yield 'OK'
        else:
            yield 'INVALID HMAC'


def conduct_simplified_handshake(address):
    dat = srp.CLIENT_LOGIN_DATA

    with contextlib.closing(socket_handshake.local_respond_handshake(address)) \
         as response_delegate:

        response_delegate.next()

        a, A = srp.simple_private_public_pair(dat.g, dat.N)

        salt, B, u = response_delegate.send((dat.email, A))

        x = srp.calculate_x(salt, dat.password)

        K = calculate_simp_K_client(B, a, u, x, dat.N)

        hmac = HMAC(K, srp.int_to_str(salt)).hexdigest()

        validation_message = response_delegate.send(hmac)

        assert validation_message == 'OK'


class MalloryServer(object):
    #login_data = {srp.CLIENT_LOGIN_DATA.email: srp.CLIENT_LOGIN_DATA}

    def respond_handshake(self):
        # pose as SimplifiedServer, use arbitrary values for b, B, u, and salt

        N, g = (srp.PUBLIC_LOGIN_DATA.N,
                srp.PUBLIC_LOGIN_DATA.g)


        email, A = yield

        b, B = srp.simple_private_public_pair(g, N)
        salt, u = srp.gen_salt(), gen_u()

        hmac = yield salt, B, u

        hmac_oracle = mk_hmac_oracle(g, N, A, salt, b, u, hmac)

        def task():
            time.sleep(0.5)
            logging.info('Begin solving password offline')
            password = solve_password(hmac_oracle)
            logging.info('Solved password: {}'.format(password))

        threading.Thread(target=task).start()

        yield 'OK'


def main():
    threading.Thread(target=socket_handshake.serve,
                     args=(LEGIT_ADDRESS, SimplifiedServer())).start()

    threading.Thread(target=socket_handshake.serve,
                     args=(MITM_ADDRESS, MalloryServer())).start()

    threading.Thread(
        target=conduct_simplified_handshake, args=(LEGIT_ADDRESS,)).run()

    time.sleep(0.5)

    threading.Thread(
        target=conduct_simplified_handshake, args=(MITM_ADDRESS,)).run()

    socket_handshake.signal_queue.put('exit')


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    main()
