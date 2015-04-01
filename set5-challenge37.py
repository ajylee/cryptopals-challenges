
import signal
import socket
import contextlib
import threading
import Queue
import select
import time
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

def _create_connection():
    while True:
        if not signal_queue.empty():
            return 1, None
        try:
            return 0, socket.create_connection((HOST, PORT))
        except socket.error, mesg:
            logging.warning('Client socket error {}: {}. Retrying.'.format(*mesg))
            time.sleep(0.05)


def local_respond_handshake():
    return_code, bare_sock = _create_connection()
    if return_code != 0:
        raise StopIteration

    with contextlib.closing(bare_sock) as sock:
        while True:
            if not signal_queue.empty():
                raise StopIteration

            readable, _w, _e = select.select([sock], [], [], 0.5)

            if sock in readable:
                remote_msg = pickle.loads(sock.recv(1024))
                logging.info('Remote: {}'.format(repr(remote_msg)))

                local_msg = yield remote_msg

                logging.info('Local:  {}'.format(repr(local_msg)))
                sock.send(pickle.dumps(local_msg))


def conduct_normal_handshake():
    c = secure_remote_password.Client()
    with contextlib.closing(local_respond_handshake()) as response_delegate:
        c.conduct_handshake(response_delegate)


def conduct_zero_key_handshake(A_factor):
    dat = secure_remote_password.mk_login_data(srp.CLIENT_LOGIN_DATA.email,
                                               'wrong password')

    with contextlib.closing(local_respond_handshake()) as response_delegate:
        response_delegate.next()
        response_delegate.send(dat.email)

        A = A_factor * dat.N

        salt, B = response_delegate.send(A)

        S = 0
        K = sha256(srp._int_to_str(S)).digest()

        hmac = HMAC(K, srp._int_to_str(salt)).hexdigest()
        validation_message = response_delegate.send(hmac)
        assert validation_message == 'OK'


def main():
    threading.Thread(target=serve).start()
    threading.Thread(target=conduct_normal_handshake).run()

    for A_factor in xrange(4):
        threading.Thread(target=conduct_zero_key_handshake, args=(A_factor,)).run()

    signal_queue.put('exit')


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.WARNING)

    main()

    # signal.pause()   # keep main thread alive
