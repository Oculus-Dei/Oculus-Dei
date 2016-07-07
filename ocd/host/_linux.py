# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Linux backend for host-based sensor
"""

import warnings
from datetime import datetime
from ocd.utils import pcall, identity, dict_acc


class LinuxBackend(object):
    def __init__(self):
        self.last = []
        self.lastb = []
        self.load()

    def load(self, **kwargs):
        """ Load the system log

        It loads log(s) from default location. If they are not in the
        default location, specify in **kwargs.

        Args:
            **kwargs: specifies custom config for sys logs.
                None for this backend.
        """
        def parse(line):
            items = filter(identity, map(lambda x: x.strip(), line.split(' ')))
            # special case
            if items[1] == 'system' and items[2] == 'boot':
                items[1] = 'system boot'
                items.pop(2)

            # time format
            tfmt = '%a %b %d %H:%M:%S %Y'
            # parse tin
            if len(items[5]) == 1:
                items[5] = '0' + items[5]  # pad zero before day
            tin = ' '.join(items[3:8])
            tin = datetime.strptime(tin, tfmt)
            # parse tout
            if items[8] == '-':
                if len(items[10]) == 1:
                    items[10] = '0' + items[10]
                if items[9] == 'crash':
                    tout = None
                else:
                    tout = ' '.join(items[9:14])
                    tout = datetime.strptime(tout, tfmt)
            else:
                tout = None

            return {
                'user':     items[0],
                'terminal': items[1],
                'ip':       items[2],
                'time_in':  tin,
                'time_out': tout,
            }

        try:
            last, bad = pcall('last -Fi')
            if bad:
                raise OSError()
            else:
                self.last = [parse(l) for l in last[:-1]]
        except OSError:
            raise Exception('`last -Fi` fails. Backend not supported.')

        try:
            lastb, bad = pcall('lastb -Fi')
            if bad:
                warnings.warn('`lastb -Fi` fails, which requires sudo permission.'
                              'Continue if you don\'t need authfailures')
            else:
                self.lastb = [parse(l) for l in lastb[:-1]]
        except OSError:
            raise Exception('`lastb -Fi` fails. Backend not supported.')

    def stat_logins(self, time_slot):
        """ Get a dict of users and their login freq
        Args:
            time_slot (tuple(datetime)): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he successful logs in
        """
        r = {}
        start, end = time_slot
        for login in self.last:
            if start <= login['time_in'] < end:
                dict_acc(r, {login['user']: 1})
        return r

    def stat_logouts(self, time_slot):
        """ Get a dict of users and their logout freq
        Args:
            time_slot (tuple(datetime)): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he logs out
        """
        r = {}
        start, end = time_slot
        for login in self.last:
            if login['time_out'] and start <= login['time_out'] < end:
                dict_acc(r, {login['user']: 1})
        return r

    def stat_authfailures(self, time_slot):
        """ Get a dict of users and their freq of authentication failure
        Args:
            time_slot (tuple(datetime)): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he failed to log in
        """
        r = {}
        start, end = time_slot
        for authfailure in self.lastb:
            if start <= authfailure['time_in'] < end:
                dict_acc(r, {authfailure['user']: 1})
        return r

    def user_activities(self, user, time_slot):
        """ Get a list of user activities within the time slot
        Args:
            user (str): the username
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime
        Returns:
            list(dict): a list of user activities, each item is in
                the format of {'activity': '...', 'ip': '...', 'time': '...'},
                where activity can be 'login', 'logout', 'authfailure',
                and time is an instance of datetime.datetime.
                Results will be sorted by time.
        """
        activities = []
        start, end = time_slot
        for login in self.last:
            if login['user'] != user:
                continue
            if start <= login['time_in'] < end:
                activities.append({
                    'activity': 'login',
                    'ip': login['ip'],
                    'time': login['time_in']
                })
            if login['time_out'] and start <= login['time_out'] < end:
                activities.append({
                    'activity': 'logout',
                    'ip': login['ip'],
                    'time': login['time_out']
                })
        for authfailure in self.lastb:
            if authfailure['user'] != user:
                continue
            if start <= authfailure['time_in'] < end:
                activities.append({
                    'activity': 'authfailure',
                    'ip': authfailure['ip'],
                    'time': authfailure['time_in']
                })
        return sorted(activities, key=lambda a: a['time'])
