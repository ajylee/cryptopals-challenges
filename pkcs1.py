

def pad(data_block, block_size):
    """
    This is the rigorous PKCS#1 described in Bleichenbacher 98.
    """

    padding_string_len = block_size - len(data_block) - 3
    return chr(0) + chr(2) + padding_string_len * chr(0xff) + chr(0) + data_block


def check_and_remove_padding(plaintext_signature, min_padding_string_len=8):
    """If valid padding, removes padding and returns tuple (True, ASN.1 HASH)
    Otherwise returns (False, None)

    This is the actual PKCS#1 described in Bleichenbacher 98.
    Not necessary for Cryptopals, but interesting for testing.

    """

    # NOTE: we cannot directly match the hash content using a regex group
    # because of possible newline chars (\n).

    fail = (False, None)

    for ii, cc in enumerate(plaintext_signature):
        if ((ii == 0 and cc == chr(0))
            or (ii == 1 and cc == chr(2))
            or (2 <= ii and cc != chr(0))):

            continue

        elif ii >= (2 + min_padding_string_len)  and cc == chr(0):
            data_block = plaintext_signature[ii + 1:]
            return (True, data_block)

        else:
            return fail

    else:
        return fail

