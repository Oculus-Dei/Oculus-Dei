# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

TODO: purpose
"""

from datetime import datetime
import pickle
from ocd.utils import pcall, I, stat, pick, cond


class MacBackend(object):
    def __init__(self):
        out, err = pcall('which opensnoop')
        if not out:
            raise Exception('opensnoop not installed!')
        self.logs = []

        out, err = pcall('dscl . -list /Users UniqueID')
        out = map(lambda l: filter(I, l.split(' ')), out)
        self.users = {int(uid): user for user, uid in out}

    def snoop(self, timeout=10, output_file=None):
        """ Snoop open's for a while

        Args:
            timeout (int): how long to snoop

            output_file (optional[str]): if specified, save log to file.
        """
        out, err = pcall('opensnoop -v', timeout)
        if len(err) > 0 and 'additional privileges' in err[0]:
            raise Exception(err[0])
        if len(out) > 0:
            out = out[1:]

        self.logs = []
        for line in out:
            line = filter(I, line.split(' '))
            time = datetime.strptime(' '.join(line[:4]), '%Y %b %d %H:%M:%S')
            user = self.users[int(line[4])]
            # TODO: this is problematic for cmd/path with space in it
            cmd = line[6]
            fpath = line[-1]
            self.logs.append({
                'time': time,
                'user': user,
                'cmd':  cmd,
                'fpath': fpath,
            })

        if output_file is not None:
            with open(output_file, 'w') as f:
                pickle.dump(self.logs, f)

    def load(self, file):
        """ Load the snoop result from file

        Args:
            file (str): the path to snoop file.
        """
        with open(file) as f:
            self.logs = pickle.load(f)

    def stat_users(self, time_slot, cmd=None, fpath=None):
        """ Count freq of users opening files

        Args:
            time_slot (tuple(datetime)): a tuple of two
                specifying the start and end time as datetime

            cmd (optional[list[str]]): a list of cmds within which
                to be filtered. Could also be a single str.

            fpath (optional[list[str]]): a list of files within which
                to be filtered. Could also be a single str.
        Returns:
            dict{str->int}: dict of users and counts
        """
        return stat(self.logs, 'user', [
            cond.in_timeslot('time', time_slot),
            cond.in_list('cmd', cmd),
            cond.in_list('fpath', fpath),
        ])

    def stat_cmds(self, time_slot=None, user=None, fpath=None):
        """ Count freq of cmds openning files

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            user (optional[list[str]]): a list of users within which
                to be filtered. Could also be a single str.

            fpath (optional[list[str]]): a list of files within which
                to be filtered. Could also be a single str.

        Returns:
            dict{str->int}: dict of cmds and counts
        """
        return stat(self.logs, 'cmd', [
            cond.in_timeslot('time', time_slot),
            cond.in_list('user', user),
            cond.in_list('fpath', fpath),
        ])

    def stat_fpaths(self, time_slot=None, user=None, cmd=None):
        """ Count freq of fpaths of openning files

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            user (optional[list[str]]): a list of users within which
                to be filtered. Could also be a single str.

            cmd (optional[list[str]]): a list of cmds within which
                to be filtered. Could also be a single str.

        Returns:
            dict{str->int}: dict of fpaths and counts
        """
        return stat(self.logs, 'fpath', [
            cond.in_timeslot('time', time_slot),
            cond.in_list('user', user),
            cond.in_list('cmd', cmd),
        ])

    def user_activities(self, user, time_slot=None, cmd=None, fpath=None):
        logs = pick(self.logs, [
            cond.in_timeslot('time', time_slot),
            cond.in_list('user', user),
            cond.in_list('cmd', cmd),
            cond.in_list('fpath', fpath),
        ])
        r = []
        for log in logs:
            x = log.copy()
            x.pop('user')
            r.append(x)
        return sorted(r, key=lambda l: l['time'])

    def cmd_activities(self, cmd, time_slot=None, user=None, fpath=None):
        logs = pick(self.logs, [
            cond.in_timeslot('time', time_slot),
            cond.in_list('user', user),
            cond.in_list('cmd', cmd),
            cond.in_list('fpath', fpath),
        ])
        r = []
        for log in logs:
            x = log.copy()
            x.pop('cmd')
            r.append(x)
        return sorted(r, key=lambda l: l['time'])

    def fpath_activities(self, fpath, time_slot=None, user=None, cmd=None):
        logs = pick(self.logs, [
            cond.in_timeslot('time', time_slot),
            cond.in_list('user', user),
            cond.in_list('cmd', cmd),
            cond.in_list('fpath', fpath),
        ])
        r = []
        for log in logs:
            x = log.copy()
            x.pop('fpath')
            r.append(x)
        return sorted(r, key=lambda l: l['time'])
