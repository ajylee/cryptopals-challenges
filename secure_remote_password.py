from collections import namedtuple
import uuid
import binascii
import random
from hashlib import sha256 
from hmac import HMAC

import number_theory.diffie_hellman as dh
import number_theory as nt


LoginData = namedtuple('LoginData', [
    'N', 'g', 'k', 'email', 'password'])


def _int_to_str(nn):
    hex_rep = hex(nn).lstrip('0x').rstrip('L')
    padded = '0' * (len(hex_rep) % 2) + hex_rep
    return binascii.unhexlify(padded)

def _str_to_int(ss):
    return long(binascii.hexlify(ss), 16)


def gen_salt():
    return random.randint(0, 0xffffffff)


def calculate_u(A, B):
    uH = sha256(_int_to_str(A + B)).digest()
    return _str_to_int(uH)

        
def calculate_x(salt, password):
    xH = sha256(_int_to_str(salt) + password).digest()
    return _str_to_int(xH)


class Server(object):
    def __init__(self):
        self.login_data = {}
        self.handshake_data = {}
        self._session_count = 0

    def new_session(self):
        _id = self._session_count 
        self._session_count += 1
        self.handshake_data[_id] = {}
        return _id

    def gen_salt_and_v(self, session_id):
        client_id = self.handshake_data[session_id]['client_id']
        dat = self.login_data[client_id]

        salt = gen_salt()

        x = calculate_x(salt, dat.password)

        v = nt.modexp(dat.g, x, dat.N)

        self.handshake_data[session_id]['salt'] = salt
        self.handshake_data[session_id]['v'] = v

    def gen_bB(self, session_id):
        client_id = self.handshake_data[session_id]['client_id']
        dat = self.login_data[client_id]

        b = dh.mod_random(dat.N)
        v = self.handshake_data[session_id]['v']
        B = dat.k * v + nt.modexp(dat.g, b, dat.N) 
        return b, B

    def get_K(self, session_id, A, b, B):
        _handshake_data = self.handshake_data[session_id]
        client_id = _handshake_data['client_id']
        dat = self.login_data[client_id]

        u = calculate_u(A, B)
        
        #  S = (A * v**u) ** b % N
        S = nt.modexp(A * nt.modexp(_handshake_data['v'], u, dat.N), b, dat.N)
        K = sha256(_int_to_str(S)).digest()
        
        _handshake_data['K'] = K
        return K
                         
    def respond_handshake(self):
        session_id = self.new_session()
        _handshake_data = self.handshake_data[session_id]

        client_id = yield

        _handshake_data['client_id'] = client_id
        self.gen_salt_and_v(session_id)
        salt = _handshake_data['salt']

        A = yield 

        b, B = self.gen_bB(session_id)
        client_hmac = yield (salt, B)

        K = self.get_K(session_id, A, b, B)

        my_hmac = HMAC(K, _int_to_str(salt)).hexdigest()

        if my_hmac == client_hmac:
            yield 'OK'
        else:
            yield 'INVALID HMAC'


class Client(object):    
    def __init__(self):
        self.user_id = uuid.uuid3(uuid.uuid4(),  # random number uuid
                               'normal client')

        self.my_login_data = None
        self.handshake_data = {}

    def conduct_handshake(self, server):
        response_delegate = server.respond_handshake()
        response_delegate.next()
        response_delegate.send(self.user_id)

        dat = self.my_login_data
        
        a = dh.mod_random(self.my_login_data.N)
        A = nt.modexp(dat.g, a, dat.N)

        salt, B = response_delegate.send(A)

        u = calculate_u(A, B)
        x = calculate_x(salt, self.my_login_data.password)

        # S = (B - k * g**x)**(a + u * x) % N
        S = nt.modexp(B - dat.k * nt.modexp(dat.g, x, dat.N), (a + u * x), dat.N)
        K = sha256(_int_to_str(S)).digest()


        self.handshake_data['K'] = K
        self.handshake_data['salt'] = salt

        hmac = HMAC(K, _int_to_str(salt)).hexdigest()
        validation_message = response_delegate.send(hmac)
        assert validation_message == 'OK'


def signup(server, client, email, password):
    data = LoginData(
        N = long(dh.NIST_P_HEX, 16),
        g = 2,
        k = 3,
        email = email,
        password = password,
    )

    server.login_data[client.user_id] = data 
    client.my_login_data = data
    

def test_SRP():
    s = Server()
    c = Client()

    email = 'abc@example.org'
    password = 'some_password'

    signup(s, c, email, password)

    c.conduct_handshake(s)


if __name__ == '__main__':
    test_SRP()
