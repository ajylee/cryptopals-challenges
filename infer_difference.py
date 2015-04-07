from __future__ import division
import random
import math as ma
from collections import Counter
import logging

logger = logging.getLogger(__name__)


def gauss_gen(mean, sigma):
    while True:
        yield random.gauss(mean, sigma)


def experimental_oracle(choices, best_choice, sigma=10.):

    generators = [gauss_gen(mean=(1. if ii == best_choice else 0.),
                            sigma=sigma)
                  for ii in choices]

    return lambda ii: next(generators[ii])


def stats(num_tries, sum_, sqr_sum):
    mean = sum_ / num_tries
    if num_tries > 3:
        sigma = ma.sqrt(sqr_sum - mean * sum_) / (num_tries - 1)
    else:
        sigma = None

    return mean, sigma


def top_ranked(tiered_rankings):
    for rankings in tiered_rankings:
        most_common = rankings.most_common(1)
        if len(most_common) > 0:
            return most_common[0][0]


class InferenceSystem(object):
    """
    :param oracle: For any X in choices, calling oracle(X) generates a gaussian
                   distribution. There exists a unique `best_choice` which has a
                   mean greater than the others.

    :param choices: An finite set of integers (or any python equivalent)


    Infer `best_choice` with :meth:`infer_best_choice`.

    """
    def __init__(self, oracle, choices):
        self.choices = choices
        self.oracle = oracle
        self.init_caches()

    def init_caches(self):
        self.num_tries = Counter()
        self.sums = Counter()
        self.sqr_sums = Counter()
        self.agreement_precision = {}

        # self.rankings[0] ranks choices that do not statistically agree with
        # some other choice; self.rankings[1] ranks choices that do.
        self.rankings = (Counter(), Counter())

        for choice in self.choices:
            self.try_(choice)
            self.try_(choice)
            self.try_(choice)
            self.update_ranking(choice)

    def try_(self, choice):
        val = self.oracle(choice)

        self.num_tries[choice] += 1
        self.sums[choice] += val
        self.sqr_sums[choice] += val**2

    def stats(self, choice):
        return stats(self.num_tries[choice], self.sums[choice], self.sqr_sums[choice])

    def choose_standard(self):
        # Choose a standard that doesn't have a high sum
        top, top_sum = self.sums.most_common(1)[0]
        top_mean = top_sum / self.num_tries[top]

        for choice in self.choices:
            if (choice != top
                and self.sums[choice] / self.num_tries[choice] < top_mean):
                return choice
        else:
            return 0

    def test_and_update_agreement(self, (choice_1, mean_1, sigma_mean_1),
                                  (choice_2, mean_2, sigma_mean_2)):
        sigma_of_difference = ma.sqrt(sigma_mean_1**2 + sigma_mean_2**2)

        agree = abs(mean_2 - mean_1) < 2 * sigma_of_difference

        for choice, sigma_mean in ((choice_1, sigma_mean_1),
                                   (choice_2, sigma_mean_2)):

            original = self.agreement_precision.get(choice)

            if original is None:
                self.agreement_precision[choice] = (agree, sigma_of_difference)
            else:
                original_agree, original_precision = original
                if sigma_of_difference < original_precision:
                    self.agreement_precision[choice] = (agree, sigma_of_difference)

        return agree, sigma_of_difference

    def update_ranking(self, choice):
        agreement_precision = self.agreement_precision.get(choice, None)
        mean = self.sums[choice] / self.num_tries[choice]

        if agreement_precision is None:
            self.rankings[0][choice] = mean
        else:
            agree, precision = agreement_precision

            if not agree:
                self.rankings[0][choice] = mean + precision
                self.rankings[1].pop(choice, None)
            else:
                self.rankings[1][choice] = precision
                self.rankings[0].pop(choice, None)

    def infer_best_choice(self, num_sigmas=10):
        """
        Find a choice such that::

            mean(oracle(choice)) - mean(oracle(standard)) > num_sigmas * uncertainty

        for some standard != choice.

        NB: at num_sigmas = 10, the probability that we return a false positive is::

            1/2 * (1 - erf(10 / sqrt(2))) --> 7.62e-24

        """
        while True:
            standard = self.choose_standard()
            self.try_(standard)
            st_mean, st_sigma_mean = self.stats(standard)

            choice = top_ranked(self.rankings)
            self.try_(choice)

            mean, sigma_mean = self.stats(choice)

            agree, sigma_of_difference = self.test_and_update_agreement(
                (standard, st_mean, st_sigma_mean),
                (choice, mean, sigma_mean))

            logger.info('standard, choice, diff, uncert = '
                        '{: >3d} {: >3d} {: >10.6f} {: >10.6f}'
                        .format(standard, choice,
                                (mean - st_mean), sigma_of_difference))

            self.update_ranking(choice)

            if (not agree
                and (mean - st_mean) > num_sigmas * sigma_of_difference
                and self.num_tries[choice] > 3
                and self.num_tries[standard] > 3):
                return choice


def test_infer_best_choice():
    choices = range(10)
    best_choice = 5
    oracle = experimental_oracle(choices, best_choice, sigma=20.)
    inf_sys = InferenceSystem(oracle, choices)
    inferred_best_choice = inf_sys.infer_best_choice()
    assert inferred_best_choice == best_choice, inferred_best_choice


if __name__ == '__main__':
    test_infer_best_choice()
