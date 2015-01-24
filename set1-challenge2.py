
import base64

def clean_flags(ss):
    return ss.rstrip('L')[2:]

def int16(s1):
    return int(s1, base=16)

def hex_XOR(s1, s2):
    return hex(int(s1, base=16) ^ int(s2, base=16))


s1 = '1c0111001f010100061a024b53535009181c'
s2 = '686974207468652062756c6c277320657965'
s3 = '746865206b696420646f6e277420706c6179'

print clean_flags(hex_XOR(s1, s2)) == s3
