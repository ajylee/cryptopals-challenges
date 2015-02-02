
def pad(cipher, strn):
    return strn + ' ' * (-len(strn) % cipher.block_size)
