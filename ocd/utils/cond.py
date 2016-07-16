# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""

import common


def _skip(*args, **kwargs):
    return True


def _make_list(x):
    if x is None:
        return []
    if not isinstance(x, list):
        x = [x]
    return x


def in_list(key, vlist):
    def cond(log):
        return log[key] in vlist
    if vlist is None:
        return _skip
    vlist = _make_list(vlist)
    return cond


def in_timeslot(key, timeslot):
    def cond(log):
        return timeslot[0] <= log[key] < timeslot[1]
    if timeslot is None:
        return _skip
    timeslot = common.solid_timeslot(timeslot)
    return cond


def stat(logs, tgt_key, where=None):
    """ Count freq of target in logs given constraints in where.

    Args:
        logs (list[dict]): logs from which to summarize

        tgt_key (str): target to be counted

        where (optional[list[cond]]): list of conditions

    Returns:
        {tgt_val1: cnt1, tgt_val2: cnt2, ...}
    """
    where = _make_list(where)
    stats = {}
    for log in logs:
        valid = True
        for cond in where:
            if not cond(log):
                valid = False
                break
        if valid:
            common.dict_acc(stats, {log[tgt_key]: 1})
    return stats


def pick(logs, where=None):
    """ Pick logs that satisfies certain conditions

    Args:
        logs (list[dict]): list of logs

        where (optional[list[cond]]): list of conditions

    Returns:
        list of valid logs
    """
    where = _make_list(where)
    good = []
    for log in logs:
        valid = True
        for cond in where:
            if not cond(log):
                valid = False
                break
        if valid:
            good.append(log)
    return good
