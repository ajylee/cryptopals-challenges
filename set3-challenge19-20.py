import base64
import string
import random
from block_crypto import CTR, strxor
import Crypto.Random
import toolz as tz
import logging

from set1_challenge3 import printable

NONCE = 0
BLOCK_SIZE = 16

COMMON_ENGLISH_CHARS = string.letters + ',. '
ALL_CHARACTERS = ''.join(map(chr, xrange(256)))
VOWELS = 'aeiouy'
CONSONANTS = ''.join(letter for letter in string.lowercase
                     if letter not in VOWELS)

COMMON_PAIRS = ['ch', 'st', 'sh', 'sm', 'sn', 'rt', 'th', 'nt', 'sp', 'nd', 'ea',
                'ay', 'tr', 'rn']
BAD_PAIRS = ['hx', 'qa', '  ', 'qe', '.t', ',t']

def score_english_char_pair(char1, char2):
    bad = ('x' in (char1, char2)
           or char1 + char2 in BAD_PAIRS)

    if bad:
        return -2

    good = ((char1 in string.letters and char2 == 's')
            or ((char1 + char2) in COMMON_PAIRS)

            # by punctuation
            or (char1 in ',.' and char2 == ' ')
            or (char2 in ',.' and char1 in string.lowercase)

                 or (char1 in ' ' and char2 in string.letters)

            # by case
            or (char1 in string.uppercase
                and char2 in string.lowercase)
            or (char2 in string.uppercase
                and char1 == ' ')

            # by vowel/consonant
            or (char1 in CONSONANTS
                and char2 in VOWELS)
            or (char2 in CONSONANTS
                and char1 in VOWELS))

    if good:
        return 1
    else:
        return 0


def guess_using_prev_byte(ciphertexts, byte_idx, prev_byte, candidates):
    score = {}

    for text in ciphertexts:
        prev_decoded = strxor(prev_byte, text[byte_idx - 1])

        for candidate in candidates:
            candidate_decoded = strxor(candidate, text[byte_idx])
            _score = score_english_char_pair(prev_decoded, candidate_decoded)
            score[candidate] = score.get(candidate, 0) + _score

    return sorted(candidates, key=lambda cand: score.get(cand, 0), reverse=True)[0]


def guess_one_key_byte(ciphertexts, byte_idx, prev_byte):
    def check(guess):
        return all(printable(strxor(byte, guess))
                   for byte in tz.pluck(byte_idx, ciphertexts))

    def score(guess):
        _score = 0
        for byte in tz.pluck(byte_idx, ciphertexts):
            if strxor(byte, guess) in COMMON_ENGLISH_CHARS:
                _score += 1
        return _score

    valid = filter(check, ALL_CHARACTERS)
    _sorted = sorted(valid, key=score, reverse=True)

    if len(ciphertexts) < 5:
        assert prev_byte is not None
        return guess_using_prev_byte(ciphertexts, byte_idx, prev_byte, _sorted)

    return _sorted[0]


def auto_guess_keystream(ciphertexts):
    max_len = max(tz.map(len, ciphertexts))

    ans = ''
    last_byte = None

    for byte_idx in xrange(max_len):
        long_enough_ciphertexts = filter(lambda t: len(t) > byte_idx, ciphertexts)
        last_byte = guess_one_key_byte(long_enough_ciphertexts, byte_idx, last_byte)
        ans += last_byte

    return ans


def manually_correct(ciphertexts, orig_keystream, manual_corrections):
    """
    For example, suppose::

        manual_corrections = {(5, 10): 'hello'}

    This indicates the plaintext starting at line 5, column 10, reads "hello".
    This information is used to correct the keystream.

    """

    new_keystream = list(orig_keystream)

    for (line_no, col_no), manual_bytes in manual_corrections.items():
        width = len(manual_bytes)
        ct = ciphertexts[line_no][col_no:col_no + width]
        new_keystream[col_no:col_no + width] = (
            list(strxor(ct, manual_bytes)))

    return ''.join(new_keystream)


def solve19():
    key = Crypto.Random.new().read(BLOCK_SIZE)
    cipher = CTR(key=key, nonce=NONCE)

    ciphertexts = []

    with open('19.txt', 'r') as fil:
        for line in fil.readlines():
            ciphertexts.append(cipher.encrypt(base64.b64decode(line)))


    k0 = auto_guess_keystream(ciphertexts)

    # Manual corrections produced after considering auto deciphered text.
    manual_corrections = {(4, 32): 'head',
                          (37, 36): 'n,',
                          (0, 0): 'I'}

    k1 = manually_correct(ciphertexts, k0, manual_corrections)


    solved_keystream = k1

    logging.info('Solved keystream: {}'
                 .format(base64.b64encode(solved_keystream)))

    column_indication_grid = '--: ' + 4 * (4 * ' ' + '.' + 4 * ' ' + '|')
    logging.info(column_indication_grid)

    for no, text in enumerate(ciphertexts):
        logging.info('{:>2}: {}'.format(no, strxor(text, solved_keystream)))


def solve20():
    key = Crypto.Random.new().read(BLOCK_SIZE)
    cipher = CTR(key=key, nonce=NONCE)

    ciphertexts = []

    with open('20.txt', 'r') as fil:
        for line in fil.readlines():
            ciphertexts.append(cipher.encrypt(base64.b64decode(line)))


    k0 = auto_guess_keystream(ciphertexts)

    # Manual corrections produced after considering auto deciphered text.
    manual_corrections = {(22, 96): 't',
                          (26, 93): 'observe, ',
                          (21, 100): ' peace',
                          (26, 105): 'whole scenery',
                          (46, 103): 'but the money', # googled "don't nothin move but"
    }

    k1 = manually_correct(ciphertexts, k0, manual_corrections)

    solved_keystream = k1

    logging.info('Solved keystream: {}'
                 .format(base64.b64encode(solved_keystream)))

    column_indication_grid = '--: ' + 4 * (4 * ' ' + '.' + 4 * ' ' + '|')
    logging.info(column_indication_grid)

    for no, text in enumerate(ciphertexts):
        logging.info('{:>2}: {}'.format(no, strxor(text, solved_keystream)))


def test_solutions():
    solve19()
    solve20()


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

    import block_crypto
    logging.getLogger(block_crypto.__name__).setLevel(logging.INFO)

    solve19()
    solve20()
