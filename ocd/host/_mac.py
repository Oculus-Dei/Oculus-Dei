# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""
import warnings
from datetime import datetime, timedelta
from ocd.utils import pcall, identity, dict_acc
from dateutil.relativedelta import relativedelta


class MacBackend(object):
    def __init__(self):
        self.last = []
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

            if items[0] == 'reboot' or items[0] == 'shutdown':
                return


            # time format
            tfmt = '%a %b %d %H:%M'

            if len(items) == 10:

                # parse tin
                if len(items[5]) == 1:
                    items[5] = '0' + items[5]  # pad zero before day
                tin = ' '.join(items[3:7])
                tin = datetime.strptime(tin, tfmt)
                now = datetime.now()
                now_month = now.month
                now_day = now.day
                tin = tin.replace(year=now.year)
                if tin.month > now_month:
                    if tin.day > now_day:
                        tin = tin - relativedelta(years = 1)


                # parse tout
                if items[7] == '-':

                    if items[8] == 'shutdown' or items[8] == 'crash' :
                        duration = items[9][1:-1]
                        if '+' in duration:
                            time = duration.split('+')
                            hours_mins = time[1].split(':')
                            tout = tin + timedelta(days = int(time[0]),\
                                                            hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                        else:
                            hours_mins = duration.split(':')
                            tout = tin + timedelta(hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                    else:
                        duration = items[9][1:-1]
                        # logout_time = items[8]
                        # logout_time = datetime.strptime(logout_time, "%H:%M")
                        if '+' in duration:
                            time = duration.split('+')
                            hours_mins = time[1].split(':')
                            tout = tin + timedelta(days = int(time[0]),\
                                                            hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                        else:
                            hours_mins = duration.split(':')
                            tout = tin + timedelta(hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                else:
                    tout = None

                return {
                    'user': items[0],
                    'terminal': items[1],
                    'ip': items[2],
                    'time_in': tin,
                    'time_out': tout,
                }

            else:
                # parse tin
                if len(items[4]) == 1:
                    items[4] = '0' + items[4]  # pad zero before day
                tin = ' '.join(items[2:6])
                tin = datetime.strptime(tin, tfmt)
                now = datetime.now()
                now_month = now.month
                now_day = now.day
                tin = tin.replace(year=now.year)
                if tin.month > now_month:
                    if tin.day > now_day:
                        tin = tin - relativedelta(years = 1)
                # parse tout
                if items[6] == '-':
                    # tout = ' '.join(items[7:9])
                    if items[7] == 'shutdown' or items[7] == 'crash' :
                        duration = items[8][1:-1]
                        if '+' in duration:
                            time = duration.split('+')
                            hours_mins = time[1].split(':')
                            tout = tin + timedelta(days = int(time[0]),\
                                                            hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                        else:
                            hours_mins = duration.split(':')
                            tout = tin + timedelta(hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                    else:

                        duration = items[8][1:-1]
                        # logout_time = items[7]

                        # logout_time = datetime.strptime(logout_time, "%H:%M")
                        if '+' in duration:
                            time = duration.split('+')
                            hours_mins = time[1].split(':')
                            tout = tin + timedelta(days = int(time[0]),\
                                                            hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                        else:
                            hours_mins = duration.split(':')
                            tout = tin + timedelta(hours = int(hours_mins[0]), \
                                                            seconds = int(hours_mins[1]) * 60)
                else:
                    tout = None

                return {
                    'user': items[0],
                    'terminal': items[1],
                    'ip': 'Local',
                    'time_in': tin,
                    'time_out': tout,
                }

        try:
            last, bad = pcall('last')
            if bad:
                raise OSError()
            else:
                self.last = [parse(l) for l in last[:-1]]
        except OSError:
            raise Exception('`last` fails. Backend not supported.')

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
            if login is not None :
            
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
            if login is not None:
                if login['time_out'] and start <= login['time_out'] < end:
                    dict_acc(r, {login['user']: 1})

        return r