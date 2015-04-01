
import signal
import socket
import sys
import threading
import contextlib
import Queue
import select
import pickle
import logging
from functools import partial
from toolz import pipe
import secure_remote_password
from hashlib import sha256
from hmac import HMAC

srp = secure_remote_password

# Handle SIGINT in main thread

signal_queue = Queue.Queue()

@partial(signal.signal, signal.SIGINT)
def handle_sigint(signal, frame):
    signal_queue.put('exit')


# make a server and client

HOST = 'localhost'
PORT = 8087


# Remote
# =======

def handle_conn(SRP_server, conn):
    response_delegate = SRP_server.respond_handshake()
    response_delegate.next()

    conn.send(pickle.dumps('welcome\n'))

    while 1:
        if not signal_queue.empty():
            break

        data = conn.recv(1024)

        if not data:
            break

        try:
            pipe(data,
               pickle.loads,
               response_delegate.send,
               pickle.dumps,
               conn.sendall)
        except StopIteration:
            break


def serve():
    SRP_server = secure_remote_password.Server()
    with contextlib.closing(socket.socket()) as s:
        s.bind((HOST, PORT))

        s.listen(10)

        while 1:
            if not signal_queue.empty():
                break

            readable, _w, _e = select.select([s], [], [], 0.5)

            if s in readable:
                conn, addr = s.accept()
                handle_conn(SRP_server, conn)


# Local
# ======

class LocalInterface(object):
    def respond_handshake(self):
        with contextlib.closing(socket.socket()) as sock:
            sock.connect((HOST, PORT))

            while 1:
                remote_msg = pickle.loads(sock.recv(1024))
                logging.info('Remote: {}'.format(repr(remote_msg)))

                local_msg = yield remote_msg

                logging.info('Local:  {}'.format(repr(local_msg)))
                sock.send(pickle.dumps(local_msg))


def conduct_normal_handshake():
    c = secure_remote_password.Client()
    s = LocalInterface()
    c.conduct_handshake(s)


def conduct_zero_key_handshake():
    server = LocalInterface()
    dat = secure_remote_password.mk_login_data(srp.CLIENT_LOGIN_DATA.email,
                                               'wrong password')

    with contextlib.closing(server.respond_handshake()) as response_delegate:
        response_delegate.next()
        response_delegate.send(dat.email)

        A = 0

        salt, B = response_delegate.send(A)

        S = 0
        K = sha256(srp._int_to_str(S)).digest()

        hmac = HMAC(K, srp._int_to_str(salt)).hexdigest()
        validation_message = response_delegate.send(hmac)
        #assert validation_message == 'OK'

        response_delegate.close()


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    threading.Thread(target=serve).start()
    threading.Thread(target=conduct_normal_handshake).run()
    threading.Thread(target=conduct_zero_key_handshake).run()

    signal_queue.put('exit')
    # signal.pause()   # keep main thread alive
