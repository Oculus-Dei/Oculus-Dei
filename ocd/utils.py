# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""


def dict_acc(d1, d2):
    """ Accumulate d2 into d1
    :param d1: dict{str->int}
    :param d2: dict{str->int}
    :return: None
    """
    for k, v in d2.iteritems():
        if k in d1:
            d1[k] += 1
        else:
            d1[k] = 1
