# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""

import os
import sys
import signal
import subprocess as sp
import threading as th
from datetime import datetime


def I(x):
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


def dict_acc(dmain, dnew):
    """ Accumulate d2 into d1
    :param dmain: dict{str->int}
    :param dnew: dict{str->int}
    :return: None
    """
    for k, v in dnew.iteritems():
        if k in dmain:
            dmain[k] += 1
        else:
            dmain[k] = 1


def pcall(cmd, timeout=None):
    """ Call a cmd separated with space
    >>> stdout, stderr = pcall('ls -al')
    >>> print stdout
    ['.', '..', ...]
    >>> print stderr
    []

    Note: empty lines will be filtered.

    Args:
        cmd (str): cmd to be called
        timeout (int): max amount of time to be run

    Returns:
        list[str]: stdout separated by lines
        list[str]: stderr separated by lines
    """
    def target():
        ps[0] = sp.Popen(cmd, shell=True, preexec_fn=os.setsid,
                         stdout=sp.PIPE, stderr=sp.PIPE)
        std[0], std[2] = ps[0].communicate()
        std[0] = filter(I, std[0].split('\n'))
        std[2] = filter(I, std[2].split('\n'))

    std = [None, None, None]
    ps = [None]
    thread = th.Thread(target=target)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() and ps[0]:
        ps[0].terminate()
        os.killpg(os.getpgid(ps[0].pid), signal.SIGTERM)
        thread.join()
    return std[0], std[2]


def sys_not_supported():
    raise NotImplementedError('System {} not supported!'
                              .format(sys.platform))
