# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""

def get_frq_dict(in_list):
    """ Convert the in_list into a dictionary. 

    The keys will be the unique elements in in_list,
    and the value will be the frequency of the element.
    :param: in_list:[str]
    :return: dict{str->int}
    """
    d = {}
    for item in in_list:
        if item in d:
            d[item] +=1
        else:
            d[item] =1
    return d


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
