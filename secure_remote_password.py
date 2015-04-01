from collections import namedtuple
import uuid
import binascii
import random
from hashlib import SHA256 

import number_theory.diffie_hellman as dh
import number_theory as nt


LoginData = namedtuple('LoginData', [
    'N', 'g', 'k', 'email', 'password'])


def _int_to_str(nn):
    return binascii.unhexlify(hex(nn).lstrip('0x').rstrip('L'))

def _str_to_int(ss):
    return long(binascii.hexlify(ss), 16)


def gen_salt():
    return random.randint(0, 0xffffffff)



class Server(object):
    def __init__(self):
        self.login_data = {}
        self.handshake_data = {}
        self._session_count = 0

    def new_sessiond():
        _id = self._session_count 
        self._session_count += 1
        self.handshake_data[_id] = {}
        return _id

    def gen_salt_and_v(self, session_id):
        client_id = self.handshake_data[session_id]['client_id']
        dat = self.login_data[client_id]

        salt = gen_salt()
        xH = SHA256(_int_to_str(salt) + login_data.password)
        x = _str_to_int(xH)
        v = nt.modexp(dat.g, x, dat.N)

        self.handshake_data[session_id, client_id] = dict(salt=salt,
                                                       v=v)

    def gen_B(self, session_id):
        client_id = self.handshake_data[session_id]['client_id']
        dat = self.login_data[client_id]

        b = dh.mod_random(dat.N)
        B = self.handshake_data['v'] + modexp(dat.g, b, dat.N) 
        return B
        
                         
    def respond_handshake(self):
        session_id = self.new_session_id()
        _handshake_data = self.handshake_data[session_id]

        client_id = yield

        _handshake_data['client_id'] = client_id
        self.gen_salt_and_v(session_id)

        A = yield 

        B = self.gen_B(session_id)
        yield self.gen_B(_handshake_data['salt'], B)

        uH = SHA256(A + B)
        u = _str_to_int(uH)


class Client(object):    
    def __inti__(self):
        self.user_id = uuid.uuid3(uuid.uuid4(),  # random number uuid
                               'normal client')

        self.my_login_data = None

    def conduct_handshake(self, client):
        response_delegate = client.respond_handshake()
        response_delegate.next()
        response_delegate.send(self.user_id)

        dat = self.my_login_data
        
        a = dh.mod_random(self.my_login_data.N)
        A = nt.modexp(dat.g, a, dat.N)

        salt, B = response_delegate.send(A)

        uH = SHA256(A + B)
        u = _str_to_int(uH)

        xH = SHA256(_int_to_str(salt) + self.my_login_data.password)
        x = _str_to_int(uH)

        S = nt.modexp((B - dat.k * nt.modexp(dat.g, x, dat.N), (a + u * x), dat.N))


def signup(server, client):
    data = LoginData(
        N = long(dh.NIST_P_HEX, 16)
        g = 2
        k = 3
        email = 'abc@example.org'
        password = 'some_password'
    )

    server.login_data[client.user_id] = data 
    client.my_login_data = data
    
