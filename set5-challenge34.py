
import os
from collections import namedtuple
import number_theory as nt
import number_theory.diffie_hellman as dh
import logging
import hash_more
import toolz as tz
from block_crypto import CBC, strip_PKCS7_padding

BLOCK_SIZE = 16  # AES block size

Message = namedtuple('Message', ['sender', 'body'])


# Crypto
# -------

def s_to_key(s):
    return str(bytearray(
        tz.take(BLOCK_SIZE,
                hash_more.SHA1(bytearray(hex(s).lstrip('0x').rstrip('L'))))))


def encrypt_secret_message(s, secret_message):
    key, iv = s_to_key(s), os.urandom(BLOCK_SIZE)
    return CBC(key, iv).encrypt(secret_message) + iv


def decrypt_secret_message(s, ciphertext_iv):
    key, iv = s_to_key(s), ciphertext_iv[-BLOCK_SIZE:]
    ciphertext = ciphertext_iv[:-BLOCK_SIZE]
    return CBC(key, iv).decrypt(ciphertext)


# Communications
# ---------------

class Communicator(object):
    def __init__(self):
        self.inbox = []
        self.listener = None

    def __repr__(self):
        return self.name

    def receive_secret_message(self, mesg):
        logging.info('{} received <secret message> from {}'.format(self, mesg.sender))
        self.inbox.append(mesg)

    def create_secret_message(self, plaintext):
        return Message(self, encrypt_secret_message(self.s, plaintext))

    def read_next_secret_message(self):
        mesg = self.inbox.pop(0)
        return self.read_secret_message(mesg)

    def read_secret_message(self, mesg):
        return strip_PKCS7_padding(decrypt_secret_message(
            self.s,
            mesg.body))

    def send_secret_message(self, plaintext):
        secret_message = self.create_secret_message(plaintext)
        self.listener.receive_secret_message(secret_message)


class Alice(Communicator):
    name = 'Alice'

    def __init__(self):
        self.p, self.g = long(dh.NIST_P_HEX, 16), dh.NIST_G
        self.a = dh.mod_random(self.p)
        self.A = nt.modexp(self.g, self.a, self.p)
        self.B = None
        Communicator.__init__(self)

    def _message_pgA(self):
        return Message(self, (self.p, self.g, self.A))

    def _receive_B(self, mesg):
        logging.info('{} received B from {}'.format(self, mesg.sender))
        self.B = mesg.body
        self.s = nt.modexp(self.B, self.a, self.p)

    def _receive_ACK(self, mesg):
        if not m_ACK.body == 'ACK':
            raise ValueError, 'did not receive ACK; handshake failed'

        logging.info('{} received ACK from {}'.format(self, mesg.sender))

    # public interface

    def connect(self, other):
        logging.info('{} connected to {}'.format(self, other))
        self.listener = other

    def conduct_handshake(self):
        """Handshake protocol from challenge 34"""
        logging.info('{} initiating handshake with {}'.format(self, self.listener))

        response_delegate = self.listener.respond_handshake()
        response_delegate.next()

        m_B = response_delegate.send(self._message_pgA())
        self._receive_B(m_B)

    def conduct_negotiated_handshake(self):
        """Handshake protocol from challenge 35"""
        logging.info('{} initiating negotiated handshake with {}'
                     .format(self, self.listener))

        response_delegate = self.listener.respond_negotiated_handshake()
        response_delegate.next()

        m_ACK = response_delegate.send(Message(self, (self.p, self.g)))
        self._receive_ACK(m_ACK)

        m_B = response_delegate.send(Message(self, self.A))
        self._receive_B(m_B)


class Bob(Communicator):
    name = 'Bob'

    def __init__(self):
        self.p, self.g = None, None
        self.A = None
        self.B = None
        self.b = None
        Communicator.__init__(self)

    def _receive_pgA(self, mesg):
        logging.info('{} received (p, g, A) from {}'.format(self, mesg.sender))
        self.p, self.g, self.A = mesg.body
        self.b = dh.mod_random(self.p)
        self.B = dh.modexp(self.g, self.b, self.p)
        self.s = nt.modexp(self.A, self.b, self.p)

    def _message_B(self):
        return Message(self, self.B)

    def _receive_pg(self, mesg):
        logging.info('{} received (p, g) from {}'.format(self, mesg.sender))
        self.p, self.g, = mesg.body
        self.b = dh.mod_random(self.p)
        self.B = dh.modexp(self.g, self.b, self.p)

    def _receive_A(self, mesg):
        logging.info('{} received A from {}'.format(self, mesg.sender))
        self.A = mesg.body
        self.s = nt.modexp(self.A, self.b, self.p)

    # public interface

    def connect(self, other):
        logging.info('{} connected to {}'.format(self, other))
        self.listener = other

    def respond_handshake(self):
        # handshake response
        mesg = yield
        self._receive_pgA(mesg)
        yield self._message_B()

    def respond_negotiated_handshake(self):
        # handshake response
        m_pg = yield
        self._receive_pg(m_pg)

        m_A = yield Message(self, 'ACK')
        self._receive_A(m_A)

        yield self._message_B()


class Mallory(Communicator):
    name = 'Mallory'

    def __init__(self):
        self.p, self.g = None, None
        self.A = None
        self.B = None
        self.s = 0
        self.alice, self.bob = None, None
        self.snooped_messages = []
        Communicator.__init__(self)

    def _receive_pgA(self, mesg):
        logging.info('{} received (p, g, A) from {}'.format(self, mesg.sender))
        self.p, self.g, _A = mesg.body

    def _receive_B(self, mesg):
        logging.info('{} received B from {}'.format(self, mesg.sender))

    def _message_pgp_as_pgA(self):
        # send (p, g, p) to Bob (expects (p, g, A))
        return Message(self, (self.p, self.g, self.p))

    def _message_p_as_B(self):
        # send p to Alice (expects B)
        return Message(self, self.p)

    def _fake_handshake(self, target):
        response_delegate = target.respond_handshake()
        response_delegate.next()
        m_B = response_delegate.send(self._message_pgp_as_pgA())
        self._receive_B(m_B)


    # public interface

    def connect(self, alice, bob):
        logging.info('{} connected to {} and {}'.format(self, alice, bob))
        self.alice, self.bob = alice, bob

    def respond_handshake(self):
        # handshake response
        m_pgA = yield
        self._receive_pgA(m_pgA)
        bob_response = self._fake_handshake(self.bob)
        yield self._message_p_as_B()

    def read_and_relay_secret_message(self):
        mesg = self.inbox.pop(0)
        logging.info('{} reading <secret message> from {}'.format(self, mesg.sender))
        self.snooped_messages.append(self.read_secret_message(mesg))
        if mesg.sender == self.bob:
            receiver = self.alice
        else:
            receiver = self.bob
        receiver.receive_secret_message(mesg)


class Mallory35(Mallory):
    """Mallory communicator for challenge 35; allows setting fake_g function"""
    def __init__(self, fake_g):
        self.fake_g = fake_g
        Mallory.__init__(self)

    def _receive_pg(self, mesg):
        logging.info('{} received (p, g) from {}'.format(self, mesg.sender))
        self.p, self.g, = mesg.body

    def _receive_A(self, mesg):
        logging.info('{} received A from {}'.format(self, mesg.sender))
        self.A = mesg.body

    def _receive_B(self, mesg):
        # OVERRIDE!!!
        logging.info('{} received B from {}'.format(self, mesg.sender))
        self.B = mesg.body

    def respond_negotiated_handshake(self):
        bob_response_delegate = self.bob.respond_negotiated_handshake()
        bob_response_delegate.next()

        m_pg = yield # from alice
        self._receive_pg(m_pg)

        m_ACK = bob_response_delegate.send(Message(self, (self.p, fake_g(self.p))))

        m_A = yield Message(self, 'ACK') # from alice
        self._receive_A(m_A)

        m_B = bob_response_delegate.send(Message(self, self.A))
        self._receive_B

        yield m_B._update(sender=self)



def conduct_direct_conversation():
    secret_text = 'secret message'

    alice = Alice()
    bob = Bob()
    alice.connect(bob)
    bob.connect(alice)

    alice.conduct_handshake()

    alice.send_secret_message(secret_text)

    bob.send_secret_message(bob.read_next_secret_message())

    assert alice.read_next_secret_message() == secret_text


def conduct_mitm_conversation():
    logging.info('')
    logging.info('*' * 50)
    logging.info('Begin MITM connection')
    logging.info('-' * 23)

    secret_text = 'secret message'

    alice = Alice()
    mallory = Mallory()
    bob = Bob()

    alice.connect(mallory)
    mallory.connect(alice, bob)
    bob.connect(mallory)

    alice.conduct_handshake()
    alice.send_secret_message(secret_text)

    mallory.read_and_relay_secret_message()

    bob.send_secret_message(bob.read_next_secret_message())

    mallory.read_and_relay_secret_message()

    alice.read_next_secret_message()

    # verify secret message
    assert mallory.snooped_messages[0] == secret_text


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    conduct_direct_conversation()
    conduct_mitm_conversation()
