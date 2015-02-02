from Crypto.Util.strxor import strxor


def pad(strn, block_size, pad_str=chr(4)):
    assert len(pad_str) == 1
    return strn + pad_str * (-len(strn) % block_size)


def xor_cipher(data, key):
    _salt = len(data) // len(key) * key + key[:len(data) % len(key)]
    return strxor(data, _salt)
