from block_crypto import CBC, random_str, chunks
from cookies import CookieSystem


class random_CBC_system(CookieSystem):
    def __init__(self):
        self.block_size = 16
        cipher = CBC(key=random_str(self.block_size),
                     iv=random_str(self.block_size))
        CookieSystem.__init__(self, cipher=cipher)


def flip_least_bit(char):
    num = ord(char)
    return chr((~num & 1) + (~1 & num))


def edit_bits(strn):
    chars = list(strn)

    to_flip = [';admin=true'.index(c) for c in ';=']

    return ''.join(
        flip_least_bit(cc)
        if ii in to_flip
        else cc
        for ii, cc in enumerate(strn))


def num_equal_from_start(seq_a, seq_b):
    for ii, (elt_a, elt_b) in enumerate(zip(seq_a, seq_b)):
        if elt_a != elt_b:
            return ii


def pre_pad_len_CBC(process_fn, block_size):
    # finds a constant pre_pad_len for AES CBC
    orig_blocks = chunks(process_fn(''), block_size)
    prev_blocks = orig_blocks

    for data_len in xrange(1, block_size * 8):
        curr_blocks = chunks(process_fn('A' * data_len), block_size)

        # get similarity
        sim_to_orig = num_equal_from_start(curr_blocks, orig_blocks)
        sim_to_prev = num_equal_from_start(curr_blocks, prev_blocks)

        if (sim_to_prev > sim_to_orig):
            # sim_to_orig == _pre_pad_len // block_size
            # data_len - 1 == -_pre_pad_len % block_size
            return sim_to_orig * block_size + (-(data_len - 1) % 16)

        prev_blocks = curr_blocks



def mk_admin_data(process_fn, block_size=16):
    _pre_pad_len = pre_pad_len_CBC(process_fn, block_size)
    assert _pre_pad_len == 32, _pre_pad_len

    lpad = 'A' * (-_pre_pad_len % 16)

    # Negate least bit of control chars before passing to process_fn
    dirt = edit_bits(';admin=true')
    ciphertext = process_fn(lpad + 'B' * block_size + dirt)

    b = chunks(ciphertext, block_size)
    edit_idx = (_pre_pad_len + len(lpad)) // 16
    b[edit_idx] = edit_bits(b[edit_idx])

    return ''.join(b)

def test_is_admin():
    server = random_CBC_system()
    ciphertext = server.cipher.encrypt('admin=true;comment=bla')
    assert server.is_admin(ciphertext)


def test_mk_admin_data():
    server = random_CBC_system()
    ciphertext = mk_admin_data(server.process_data, block_size=16)
    assert server.is_admin(ciphertext)


if __name__ == '__main__':
    test_mk_admin_data()
