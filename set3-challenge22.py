import datetime, calendar
from my_random import MersenneTwister


def solve_seed(first_mt_number, current_time_stamp, max_seconds_back):

    for ts in xrange(current_time_stamp - max_seconds_back,
                     current_time_stamp + 1):
        nn = MersenneTwister(ts).extract_number()

        if nn == first_mt_number:
            return ts
    else:
        raise(ValueError, 'Failed to solve for seed')


def future_timestamp(**timedelta_kwargs):
    future = datetime.datetime.utcnow() + datetime.timedelta(**timedelta_kwargs)
    return calendar.timegm(future.timetuple())


def test_solve_seed():
    # seed_time and post_pad_time are "secret"
    seed_time = 352
    post_pad_time = 724
    seed = future_timestamp(seconds=seed_time)

    # prn and return time are known to user
    prn = MersenneTwister(seed).extract_number()
    return_time = seed_time + post_pad_time

    assert seed == solve_seed(prn, future_timestamp(seconds=return_time), return_time)
    

if __name__ == '__main__':
    test_solve_seed()
