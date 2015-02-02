

def pad(strn, block_size, pad_str=chr(4)):
    assert len(pad_str) == 1
    return strn + pad_str * (-len(strn) % block_size)
