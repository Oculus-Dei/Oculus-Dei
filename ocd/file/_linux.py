# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Opensnoop wrapper for linux
"""

from ocd.utils import pcall, I


class LinuxBackend(object):
    def __init__(self):
        pass

    def snoop(self, timeout=10):
        """ Snoop open's for a while

        Args:
            timeout (int): how long to snoop
        """
        pass

    def unique_users(self, time_slot=None, cmd=None, fpath=None):
        """ Unique api for stat_users. See stat_users for detail. """
        return self.stat_users(time_slot, cmd, fpath)

    def unique_cmds(self, time_slot=None, user=None, fpath=None):
        """ Unique api for stat_cmds. See stat_cmds for detail. """
        return self.stat_cmds(time_slot, user, fpath)

    def unique_fpaths(self, time_slot=None, user=None, cmd=None):
        """ Unique api for stat_fpaths. See stat_fpaths for detail. """
        return self.stat_fpaths(time_slot, user, cmd)

    def stat_users(self, time_slot=None, cmd=None, fpath=None):
        """ Count freq of users opening files

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            cmd (optional[list[str]]): a list of cmds within which
                to be filtered. Could also be a single str.

            fpath (optional[list[str]]): a list of files within which
                to be filtered. Could also be a single str.
        Returns:
            dict{str->int}: dict of users and counts
        """
        time_slot = solid_timeslot(time_slot)
        cmd = [cmd] if isinstance(cmd, str) else cmd
        fpath = [fpath] if isinstance(fpath, str) else fpath
        return self.backend.stat_users(time_slot, cmd, fpath)

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
        time_slot = solid_timeslot(time_slot)
        user = [user] if isinstance(user, str) else user
        fpath = [fpath] if isinstance(fpath, str) else fpath
        return self.backend.stat_cmds(time_slot, user, fpath)

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
        time_slot = solid_timeslot(time_slot)
        user = [user] if isinstance(user, str) else user
        cmd = [cmd] if isinstance(cmd, str) else cmd
        return self.backend.stat_fpaths(time_slot, user, cmd)

    def fpath_activities(self, fpath, time_slot=None, user=None, cmd=None):
        """ Give a list of activities done to the file. Sorted by time.

        Args:
            fpath: the file path to look for.

            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            user (optional[list[str]]): a list of users within which
                to be filtered. Could also be a single str.

            cmd (optional[list[str]]): a list of cmds within which
                to be filtered. Could also be a single str.

        Returns:
            list[{'user': xxx, 'cmd': xxx, 'time': xxx}]
        """
        time_slot = solid_timeslot(time_slot)
        user = [user] if isinstance(user, str) else user
        cmd = [cmd] if isinstance(cmd, str) else cmd
        return self.backend.fpath_activities(time_slot, user, cmd)

