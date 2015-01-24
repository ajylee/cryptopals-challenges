

from set1_challenge3 import cipher
import binascii


def solve():
    
    _inp = ("Burning 'em, if you ain't quick and nimble\n"
            "I go crazy when I hear a cymbal")

    _desired_ans = (
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )

    _calc_ans = binascii.hexlify(cipher(_inp, 'ICE'))

    print _calc_ans == _desired_ans


def extra():
    _i1 = """Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this."""
    _o1 = binascii.hexlify(cipher(_i1, 'ICEBEH'))
    return _o1

    
if __name__ == '__main__':
    solve()
    