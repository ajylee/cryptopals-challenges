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

COMMON_ENGLISH_CHARS = string.letters + ',.;:!?\'- '
ALL_CHARACTERS = ''.join(map(chr, xrange(256)))
VOWELS = 'aeiouy'
CONSONANTS = ''.join(letter for letter in string.lowercase
                     if letter not in VOWELS)

COMMON_SEQUENCES = [' a ', ' I ', 'the', 'and', 'low', 'bow', 'oat', 'upp', 'opp',
                    'int', 'abl', 'ble', 'thi', 'she', 'his', 'sed', 'ith', 'was',
                    'ant', 'ean', 'ing', 'ty ', 'has',
                    'com', 'swe', 'win', 'viv'
                    'his '
                    ' of ', ' in ', 'cent',
                    'with', 'most', 'kept', 'fire',]



def check_key_part(ciphertexts, key_idx, key_part):
    score = 0

    for text in ciphertexts:
        if len(text) > key_idx:
            relevant_text = text[key_idx:key_idx + len(key_part)]
            trial_plaintext = strxor(key_part[:len(relevant_text)], relevant_text)
            if any(byte not in COMMON_ENGLISH_CHARS for byte in trial_plaintext):
                return False
            else:
                # there should be more letters than anything else
                for byte in trial_plaintext:
                    if byte in string.letters:
                        score += 1
                    else:
                        score -= 3
    else:
        return score > 0


def try_sequence(ciphertexts, trial_sequence):
    results = []

    for row, text in enumerate(ciphertexts):
        for key_idx in xrange(len(text) - len(trial_sequence)):
            key_part = strxor(text[key_idx:key_idx + len(trial_sequence)], trial_sequence)
            if check_key_part(ciphertexts, key_idx, key_part):
                results.append((key_idx, key_part))

    return results
            

def try_sequences(ciphertexts, trial_sequences):
    key = [' '] * max(tz.map(len, ciphertexts))
    print len(key)

    for seq in trial_sequences:
        results = try_sequence(ciphertexts, seq)
        for result in results:
            key_idx, key_part = result
            key[key_idx:key_idx + len(key_part)] = key_part

    return ''.join(key)


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


    k0 = try_sequences(ciphertexts, COMMON_SEQUENCES)

    # Manual corrections produced after considering auto deciphered text.
    manual_corrections = {
        (4, 32): 'head',
        (37, 36): 'n,',
        (0, 0): 'I have met the ',
        (1, 0): 'Coming with vivid faces',
    }

    k1 = manually_correct(ciphertexts, k0, manual_corrections)


    solved_keystream = k1

    logging.info('Solved keystream: {}'
                 .format(base64.b64encode(solved_keystream)))

    column_indication_grid = '--: ' + 4 * (4 * ' ' + '.' + 4 * ' ' + '|')
    logging.info(column_indication_grid)

    for no, text in enumerate(ciphertexts):
        logging.info('{:>2}: {}'.format(no, repr(strxor(text, solved_keystream))))


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    import block_crypto
    logging.getLogger(block_crypto.__name__).setLevel(logging.INFO)
    solve19()
