# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Windows backend for host-based sensor
"""


class WindowsBackend(object):
    def load(self, **kwargs):
        """ Load the system log

        It loads log(s) from default location. If they are not in the
        default location, specify in **kwargs.

        TODO: document kwargs necessary for log location

        Args:
            **kwargs: specifies custom config for sys logs
        """
        pass

    def unique_logins(self, time_slot=None):
        """ Get the unique users logged in within a period
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            set(str): unique set of users
        """
        pass

    def unique_logouts(self, time_slot=None):
        """ Get the unique users logged in within a period
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            set(str): unique set of users
        """
        pass

    def unique_authfailures(self, time_slot=None):
        """ Get the unique users failed in logging in within a period
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            set(str): unique set of users
        """
        pass

    def stat_logins(self, time_slot=None):
        """ Get a dict of users and their login freq
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            dict(str->int): user vs how many times he successful logs in
        """
        pass

    def stat_logouts(self, time_slot=None):
        """ Get a dict of users and their logout freq
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            dict(str->int): user vs how many times he logs out
        """
        pass

    def stat_authfailures(self, time_slot=None):
        """ Get a dict of users and their freq of authentication failure
        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            dict(str->int): user vs how many times he failed to log in
        """
        pass

    def user_activities(self, user, time_slot=None):
        """ Get a list of user activities within the time slot
        Args:
            user (str): the username
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
        Returns:
            list(dict): a list of user activities, each item is in
                the format of {'activity': '...', 'time': '...'},
                where activity can be 'login', 'logout', 'authfailure',
                and time is an instance of datetime.datetime
        """
        pass
