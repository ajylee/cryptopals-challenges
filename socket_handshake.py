import signal
import socket
import contextlib
import Queue
import select
import time
import pickle
import logging
from functools import partial
from toolz import pipe

logger = logging.getLogger(__name__)


# Handle SIGINT in main thread

signal_queue = Queue.Queue()

@partial(signal.signal, signal.SIGINT)
def handle_sigint(signal, frame):
    signal_queue.put('exit')


# Remote
# =======

def handle_conn(response_delegate, conn):
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


def serve(address, handshake_server):
    with contextlib.closing(socket.socket()) as s:
        s.bind(address)

        s.listen(10)

        while 1:
            if not signal_queue.empty():
                break

            readable, _w, _e = select.select([s], [], [], 0.5)

            if s in readable:
                conn, addr = s.accept()
                handle_conn(handshake_server.respond_handshake(), conn)


# Local
# ======

def _create_connection(address):
    while True:
        if not signal_queue.empty():
            return 1, None
        try:
            return 0, socket.create_connection(address)
        except socket.error, mesg:
            logger.warning('Client socket error {}: {}. Retrying.'.format(*mesg))
            time.sleep(0.05)


def local_respond_handshake(address):
    return_code, bare_sock = _create_connection(address)
    if return_code != 0:
        raise StopIteration

    with contextlib.closing(bare_sock) as sock:
        while True:
            if not signal_queue.empty():
                raise StopIteration

            readable, _w, _e = select.select([sock], [], [], 0.5)

            if sock in readable:
                remote_msg = pickle.loads(sock.recv(1024))
                logger.info('Remote: {}'.format(repr(remote_msg)))

                local_msg = yield remote_msg

                logger.info('Local:  {}'.format(repr(local_msg)))
                sock.send(pickle.dumps(local_msg))
