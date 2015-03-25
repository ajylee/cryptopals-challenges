CONTROL_CHARS = ';='


def quote(strn):
    def _quote_char(strn, char):
        return strn.replace(char, '\\' + char)

    return reduce(_quote_char, CONTROL_CHARS, strn)


def sandwich(strn):
    pre = "comment1=cooking%20MCs;userdata="
    post = ";comment2=%20like%20a%20pound%20of%20bacon"
    return ''.join([pre, strn, post])


class CookieSystem(object):
    def __init__(self, cipher):
        self.cipher = cipher

    def process_data(self, userdata):
        return self.cipher.encrypt(sandwich(quote(userdata)))

    def is_admin(self, ciphertext):
        plain = self.cipher.decrypt(ciphertext)
        return 'admin=true' in plain.split(';')


# =======
# Tests
# =======

class TestCipher(object):
    def encrypt(self, text):
        return text

    def decrypt(self, text):
        return text
        

def test_quote():
    assert quote('abc;123') == r'abc\;123'
    assert quote('abc=123') == r'abc\=123'


def test_is_admin():
    server = CookieSystem(TestCipher())
    ciphertext = server.cipher.encrypt('admin=true;comment=bla')
    assert server.is_admin(ciphertext)
