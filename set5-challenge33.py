import number_theory.diffie_hellman as df


class GenP(object):
    def __init__(self):
        self.count = 0

    def mod_random(self, p):
        self.count += 1 % 2
        return (16 if self.count % 2 else 20)


if __name__ == '__main__':
    DEBUG = True
    df.easy_diffie_hellman()
    df.nist_diffie_hellman()

    # Dangerous! 'Monkey patching' mod_random
    df.mod_random = GenP().mod_random

    assert df.diffie_hellman(37, 5) == df.simple_diffie_hellman(37, 5)
