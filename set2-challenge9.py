from block_crypto import pad

assert pad("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
