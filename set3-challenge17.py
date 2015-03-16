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


from random import randint, rand_str
from block_crypto import CBC


POSSIBLE_PREPADS = """
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
