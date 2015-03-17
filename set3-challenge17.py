# Thorough strategy:
#
# Notation:
# hit - A hit is a piece of ciphertext that the oracle says is valid PKCS#7.
#
# Starting on the last byte of the last block, XOR with every possibility.
#
# For each hit, check if it is 0x01 and if so, continue to next step.
# To check, vary byte -2 randomly once and check if we still have a hit.
# The last byte is 0x01 iff we have a hit.
#
# Use XOR to set last byte to 0x02.
# Move to block -2, try every XOR possibility.
# If every possibility is a hit, then the last byte has actually been set to 0x01.
# Assume each hit is 0x02.
# Use XOR to set last two bytes to 0x03.
# Continue.


import random
import Crypto.Random
from block_crypto import (RandCBC, strxor, pad, valid_PKCS7_padding,
                          strip_PKCS7_padding)
import toolz
from copy import copy
import logging


POSSIBLE_PLAINTEXTS = """
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
""".strip().split('\n')

BLOCK_SIZE = 16


def string_assoc(strn, idx, char):
    return strn[:idx] + char + strn[idx + 1:]


def _gen_chrs():
    return (chr(ii) for ii in xrange(256))


def assoc_solved_bytes(block_size, ciphertext, solved_bytes, replacement_chr):
    text = ciphertext

    for byte_idx in xrange(-len(solved_bytes), 0):
        xor_byte = strxor(
            strxor(ciphertext[byte_idx - block_size], solved_bytes[byte_idx]),
            replacement_chr)
        text = string_assoc(text, byte_idx - block_size, xor_byte)

    return text


def solve_byte(PKCS7_oracle, block_size, ciphertext, byte_pos, solved_bytes):
    padding_chr = chr(len(solved_bytes) + 1)
    pad_edited = assoc_solved_bytes(block_size, ciphertext, solved_bytes, padding_chr)

    for _xor_byte in _gen_chrs():
        _trial_text = string_assoc(pad_edited, byte_pos - block_size, _xor_byte)
        if PKCS7_oracle(_trial_text):

            solved_byte = chr(ord(padding_chr)
                              ^ ord(_xor_byte)
                              ^ ord(ciphertext[byte_pos - block_size]))

            yield solved_byte


def solve_last_byte(PKCS7_oracle, block_size, ciphertext):
    byte_pos = -1
    solved_bytes = ''

    for _trial_solved_byte in solve_byte(
            PKCS7_oracle, block_size, ciphertext, byte_pos, solved_bytes):

        pad_edited = assoc_solved_bytes(block_size, ciphertext,
                                        _trial_solved_byte, chr(1))
        _vary_idx = byte_pos - block_size - 1
        _variation = string_assoc(pad_edited, _vary_idx,
                                  chr((ord(pad_edited[_vary_idx]) + 1) % 256))

        if PKCS7_oracle(_variation):
            return _trial_solved_byte

    raise ValueError


def solve_last_block(PKCS7_oracle, block_size, ciphertext):
    solved_bytes = solve_last_byte(
        PKCS7_oracle, block_size, ciphertext=ciphertext)

    for byte_pos in xrange(-2, -block_size - 1, -1):
        solved_bytes = (
            toolz.first(solve_byte(PKCS7_oracle, block_size,
                                   ciphertext, byte_pos, solved_bytes))
            + solved_bytes
        )

    logging.debug('solved_bytes {}'.format(repr(solved_bytes)))
    return solved_bytes


def solve_ciphertext(PKCS7_oracle, block_size, ciphertext):
    nblocks = len(ciphertext) // block_size - 1  # (first block is IV)
    solved_text = ''

    for block_ii in xrange(-1, -nblocks - 1, -1):
        rstrip_len = (block_ii + 1) * block_size

        if rstrip_len != 0:
            lopped = ciphertext[:rstrip_len]
        else:
            lopped = ciphertext

        solved_text = (solve_last_block(PKCS7_oracle, block_size, lopped)
                       + solved_text)

    return solved_text


def test_solve_last_byte():
    plaintext = random.choice(POSSIBLE_PLAINTEXTS)
    padded = pad(plaintext, BLOCK_SIZE)

    cipher = RandCBC(BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext)

    oracle = toolz.compose(valid_PKCS7_padding, cipher.decrypt)

    assert (
        solve_last_byte(oracle, BLOCK_SIZE, ciphertext)
        == padded[-1]
    )


def test_break_PKCS7_oracle():
    block_size = BLOCK_SIZE

    plaintext = random.choice(POSSIBLE_PLAINTEXTS)

    cipher = RandCBC(BLOCK_SIZE)
    ciphertext = cipher.encrypt(plaintext)

    oracle = toolz.compose(valid_PKCS7_padding, cipher.decrypt)

    ans = strip_PKCS7_padding(solve_ciphertext(
            oracle, block_size=BLOCK_SIZE, ciphertext=ciphertext))

    logging.info(repr(plaintext))
    logging.info(repr(ans))

    assert ans == plaintext


def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)
    test_solve_last_byte()
    for ii in xrange(5):
        test_break_PKCS7_oracle()


if __name__ == '__main__':
    main()
