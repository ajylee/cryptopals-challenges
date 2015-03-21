import toolz as tz

def _lowest_32_bits(n):
    return ((1 << 32) - 1) & n

class MersenneTwister(object):
    def __init__(self, seed):
        self.state = [0] * 624
        self.index = 0
        self.initialize_generator(seed)

    def initialize_generator(self, seed):
        self.index = 0
        self.state[0] = seed

        for ii in xrange(1, len(self.state)):
            self.state[ii] = _lowest_32_bits(
                1812433253 * (self.state[ii-1] ^ (self.state[ii-1] >> 30)) + ii)

    def extract_number(self):
        # Extract a tempered pseudorandom number based on the index-th value,
        # calling generate_numbers() every 624 numbers
        if self.index == 0:
            self.generate_numbers()

        nn = tz.pipe(self.state[self.index],
                   lambda y: y ^ (y >> 11),
                   lambda y: y ^ ((y << 7) & 2636928640),
                   lambda y: y ^ ((y << 15) & 4022730752),
                   lambda y: y ^ (y >> 18))

        self.index = (self.index + 1) % len(self.state)
        return nn

    def generate_numbers(self):
        # Generate an array of 624 untempered numbers

        for ii in xrange(len(self.state)):
            y = ((self.state[ii] & 0x80000000) +
                 ((self.state[(ii+1) % len(self.state)]) & 0x7fffffff))

            self.state[ii] = self.state[(ii + 397) % len(self.state)] ^ (y >> 1)
            if y % 2 != 0:
                self.state[ii] = self.state[ii] ^ 2567483615


def test_mersenne_twister():
    seed = 0x3ab10e3471c1
    mt = MersenneTwister(seed)

    count = {}

    for ii in xrange((2 << 20) - 1):
        if ii % (2 << 18) == 0:
            print len(bin(ii)) - 2, bin(ii)

        n = mt.extract_number()
        count[n] = count.get(n, 0) + 1


    #import matplotlib.pyplot as plt
    #import numpy as np

    #x = np.array(count.keys())
    #y = np.array([count[k] for k in x])

    #plt.ion()
    #plt.clf()
    #plt.plot(x, y, ls='None', marker='o')
    #plt.show()


if __name__ == '__main__':
    test_mersenne_twister()
