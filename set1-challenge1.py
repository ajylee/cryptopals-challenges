

import toolz
import binascii

test_input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

test_output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

def b16_to_b64(ss):
    return toolz.pipe(ss, binascii.a2b_hex, binascii.b2a_base64)


assert b16_to_b64(test_input) == test_output
    