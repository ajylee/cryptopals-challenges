import toolz as tz

import pprint
import itertools
import base64
import binascii

import matplotlib.pyplot as plt
import numpy as np

from Crypto.Cipher import AES
from Crypto import Random

from set1_challenge6 import chunks, average_hamming

def score(ss, max_chunks=10):
    num_chunks = min(len(ss) / 16, max_chunks)
    return average_hamming(chunks(ss, 16, num_chunks)) / 8.


def solve():
    with open('8.txt') as fil:
        ciphertexts = map(binascii.unhexlify, fil.read().split())

    scores = map(score, ciphertexts)
    index = scores.index(min(scores))
    candidate = ciphertexts[index]

    return index, candidate, scores


def plot_scores(scores):

    plt.ion()
    plt.clf()
    plt.hist(scores, bins=np.linspace(.4, .6, 200),
             histtype=u'step', normed=True)

    plt.show()


def experiment():
    random = Random.new()

    def rand(num_blocks):
        return random.read(AES.block_size * num_blocks)

    _rep = rand(1)
    nreps = 4
    ss = _rep * nreps + rand(10 - nreps)

    for ii in xrange(10):
        key = rand(1)
        cipher = AES.new(key, AES.MODE_ECB)
        print score(cipher.encrypt(ss))


if __name__ == '__main__':
    index, cand, scores = solve()
    plot_scores(scores)

    freqs = tz.frequencies(chunks(cand, 16, len(cand)/16))
    pprint.pprint(freqs)
