
import signal
import contextlib
import threading
import logging
import secure_remote_password as srp
from hashlib import sha256
from hmac import HMAC
import socket_handshake


# make a server and client

HOST = 'localhost'
PORT = 8087
ADDRESS = (HOST, PORT)


def conduct_normal_handshake(address):
    c = srp.Client()
    with contextlib.closing(socket_handshake.local_respond_handshake(address)) \
         as response_delegate:
        c.conduct_handshake(response_delegate)


def conduct_zero_key_handshake(address, A_factor):
    dat = srp.mk_login_data(srp.CLIENT_LOGIN_DATA.email,
                            'wrong password')

    with contextlib.closing(socket_handshake.local_respond_handshake(address)) \
         as response_delegate:
        response_delegate.next()
        response_delegate.send(dat.email)

        A = A_factor * dat.N

        salt, B = response_delegate.send(A)

        S = 0
        K = sha256(srp.int_to_str(S)).digest()

        hmac = HMAC(K, srp.int_to_str(salt)).hexdigest()
        validation_message = response_delegate.send(hmac)
        assert validation_message == 'OK'


def main():
    threading.Thread(target=socket_handshake.serve, args=(ADDRESS, srp.Server())).start()
    threading.Thread(target=conduct_normal_handshake, args=(ADDRESS,)).run()

    for A_factor in xrange(4):
        threading.Thread(target=conduct_zero_key_handshake,
                         args=(ADDRESS, A_factor,)).run()

    socket_handshake.signal_queue.put('exit')


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.WARNING)

    main()

    # signal.pause()   # keep main thread alive
