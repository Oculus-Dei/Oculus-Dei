# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""



import warnings
from datetime import datetime
from ocd.utils import pcall_pipeline, identity, get_frq_dict


class MacBackend(object):
    def __init__(self):
		self.authf = {}

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
            authf_local,bad = pcall_pipeline('syslog -F \'$((Time)(J)) $Host $(Sender)[$(PID)]<$((Level)(str))>: $Message\' | grep \'Failed to authenticate\'')
            if bad:
                raise OSError()
            authf_ssh,bad = pcall_pipeline('syslog -F \'$((Time)(J)) $Host $(Sender)[$(PID)]<$((Level)(str))>: $Message\' | grep \'PAM: authentication error\'')
            if bad:
                raise OSError()
            self.authf['local'] = [parse_auth('local',l) for l in authf_local]
            print(self.authf['local'])
            self.authf['ssh'] = [parse_auth('ssh',l)  for l in authf_ssh]
            print(self.authf['ssh'])
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
        self.load_auth_data()
        

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
        pass