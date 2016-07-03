# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""
import warnings
from datetime import datetime, timedelta
from ocd.utils import (pcall, identity, dict_acc,
                       pcall, get_frq_dict)
from dateutil.relativedelta import relativedelta



class MacBackend(object):
    def __init__(self):
        self.last = []
        self.authf = {}
        self.load()


    def load_auth_data(self,**kwargs):
        def parse_auth(auth_type,line):
            items = filter(identity, map(lambda x: x.strip(), line.split(' ')))
            tfmt = '%Y-%m-%d %H:%M:%S'
            time = items[0]+' '+items[1]
            time = datetime.strptime(time, tfmt)
            if auth_type == 'local':
                return{
                    'user':items[8][1:len(items[8])-1],
                    'ip':None,
                    'time': time,
                }
            elif auth_type == 'ssh':
                return{
                    'user':items[9],
                    'ip':items[11],
                    'time': time,
                }
                
        try:
            authf_local,bad = pcall('syslog -F \'$((Time)(J)) $Host $(Sender)[$(PID)]<$((Level)(str))>: $Message\' | grep \'Failed to authenticate\'')
            if bad:
                raise OSError()
            authf_ssh,bad = pcall('syslog -F \'$((Time)(J)) $Host $(Sender)[$(PID)]<$((Level)(str))>: $Message\' | grep \'PAM: authentication error\'')
            if bad:
                raise OSError()
            self.authf['local'] = [parse_auth('local',l) for l in authf_local]

            self.authf['ssh'] = [parse_auth('ssh',l)  for l in authf_ssh]
        except OSError:
            raise Exception('`syslog` fails. Backend not supported.')


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
                self.last = filter(identity, [parse(l) for l in last[:-1]])

            self.load_auth_data()
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
        

    def stat_authfailures(self, time_slot=None):
        """ Get a dict of users and their freq of authentication failure
        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he failed to log in
        """
        auth_total=[]
        start, end = time_slot
        for a in self.authf['local']:
            if start <= a['time'] < end:
                auth_total.append(a['user']) #users
        for a in self.authf['ssh']:
            if start <= a['time'] < end:
                auth_total.append(a['user']) #users
        return get_frq_dict(auth_total)

    def user_activities(self, user, time_slot=None):
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
            if login['user'] == user:
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
        for conn_type in self.authf:
            for authfailure in self.authf[conn_type]:
                if authfailure['user']== user:
                    if start <= authfailure['time'] < end:
                        activities.append({
                            'activity': 'authfailure',
                            'ip': authfailure['ip'],
                            'time': authfailure['time']
                        })
        return sorted(activities, key=lambda a: a['time'])

