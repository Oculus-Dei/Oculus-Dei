# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""

import subprocess as sp
from datetime import datetime


def identity(x):
    return x


def dt2ts(dt):
    """
    Convert datetime to timestamp
    :param dt: datetime
    :return: timestamp
    """
    return (dt - datetime(1970, 1, 1)).total_seconds()


def solid_timeslot(time_slot):
    if not time_slot:
        start, end = None, None
    else:
        start, end = time_slot
    if not start:
        start = datetime(1970, 1, 1)
    if not end:
        end = datetime.now()
    return start, end


def timeslot_with_timestamps(time_slot):
    start, end = solid_timeslot(time_slot)
    start = dt2ts(start)
    end = dt2ts(end)
    return start, end


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
            d[item] += 1
        else:
            d[item] = 1
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


def pcall_pipeline(cmd):
    p=sp.Popen(cmd,shell=True,stdout=sp.PIPE, stderr=sp.PIPE)
    stdout, stderr = p.communicate()
    stdout = filter(identity, stdout.split('\n'))
    stderr = filter(identity, stderr.split('\n'))
    return stdout, stderr

def pcall(cmd):
    """ Call a cmd separated with space
    >>> stdout, stderr = pcall('ls -al')
    >>> print stdout
    ['.', '..', ...]
    >>> print stderr
    []

    Note: empty lines will be filtered.

    Args:
        cmd (str): cmd to be called

    Returns:
        list[str]: stdout separated by lines
        list[str]: stderr separated by lines
    """
    cmd = filter(identity, cmd.split(' '))
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
    stdout, stderr = p.communicate()
    stdout = filter(identity, stdout.split('\n'))
    stderr = filter(identity, stderr.split('\n'))
    return stdout, stderr
