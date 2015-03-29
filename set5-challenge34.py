
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


class Communicator(object):
    def __init__(self, name):
        self.inbox = []  # list of messages
        self.name = name

    def __repr__(self):
        return 'Communicator {}'.format(self.name)

    def send(self, other, body):
        message = Message(sender=self, body=body) 
        other.inbox.append(message)

    def read_message(self):
        if self.inbox:
            return self.inbox.pop(0)


class Contacts:
    alice = 'Alice'
    bob = 'Bob'
    mallory = 'Mallory'

    
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


def protocol_A(secret_message):
    """Message Protocol from A point of view"""
    me = Contacts.alice
    other = yield

    yield
    logging.info('{} set up connection with {}'.format(me, other))
    
    p, g = (long(dh.NIST_P_HEX, 16), dh.NIST_G, )
    a = dh.mod_random(p)
    A = nt.modexp(g, a, p)
    m0 = Message(me, (p, g, A))

    m1 = other.send(m0)
    logging.info('{} received B'.format(me))

    B = m1.body
    s = nt.modexp(B, a, p)
    m2 = Message(me, encrypt_secret_message(s, secret_message))

    m3 = other.send(m2)
    logging.info('{} received secret message'.format(me))

    assert strip_PKCS7_padding(decrypt_secret_message(s, m3.body)) \
        == secret_message

    yield

    
def protocol_B():
    me = Contacts.bob
    other = yield

    logging.info('{} set up connection with {}'.format(me, other))

    m0 = yield
    logging.info('{} received (p, g, A)'.format(me))

    p, g, A = m0.body
    b = dh.mod_random(p)
    B = dh.modexp(g, b, p)
    m1 = Message(me, B)

    m2 = yield m1
    logging.info('{} received secret message'.format(me))

    s = nt.modexp(A, b, p)
    
    secret_message = strip_PKCS7_padding(decrypt_secret_message(s, m2.body))
    m3 = Message(me, encrypt_secret_message(s, secret_message))

    yield m3


def protocol_MITM():
    alice, bob = yield

    m0 = yield  # from alice
    assert m0.sender == contacts.alice
    p, g, A = m0.body
    fake_m0 = Message(contacts.alice, (p, g, p))

    m1 = yield
    
        
def execute_direct_connection():
    secret_message = 'secret message'

    # initialize generators
    alice = protocol_A(secret_message)
    bob = protocol_B()
    alice.next()
    bob.next()

    # initialize connection
    bob.send(alice)
    alice.send(bob)

    # communicate
    alice.next()

    
def execute_mitm_connection():
    secret_message = 'secret message'

    # initialize generators
    alice = protocol_A(secret_message)
    bob = protocol_B()
    alice.next()
    bob.next()

    # initialize connection
    bob.send(alice)
    alice.send(bob)

    # communicate
    alice.next()

    
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    execute_direct_connection()
