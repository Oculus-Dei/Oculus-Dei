# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Main API for sensors
"""

import sys
from datetime import datetime
from utils import solid_timeslot, timeslot_with_timestamps


class Sensor(object):
    def __init__(self):
        pass


class NetworkSensor(Sensor):
    """ Network sensor for packet analysis """

    def __init__(self, backend='pyshark'):
        """ Init a network sensor

        Args:
            backend (str): either 'pyshark' or 'scapy'
        """
        super(NetworkSensor, self).__init__()
        if backend == 'pyshark':
            from network._pyshark import PysharkWrapper
            self.wrapper = PysharkWrapper()
        elif backend == 'scapy':
            from network._scapy import ScapyWrapper
            self.wrapper = ScapyWrapper()
        else:
            raise NotImplementedError('Backend not supported!')

    def sniff(self, interface, timeout=5):
        """Sniff from an interface for a period of time

        Args:
            interface (str): the interface to sniff from, e.g. en0

            timeout (optional[int]): time to sniff
        """
        self.wrapper.sniff(interface, timeout)

    def load(self, capfile):
        """Load a capture file. Backend could change accordingly.

        Args:
            capfile: capture file
        """
        self.wrapper.load(capfile)

    def unique_macs(self, time_slot=None, ip=None):
        """Get a unique set of MAC addresses within the capture

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            ip (optional[list(str)]):

        Returns:
            list(str): mac addresses
        """

        return self.stat_macs(time_slot, ip).keys()

    def unique_ips(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a unique set of ips within the capture

        It can be either src ip or dst ip. If src ip is specified,
        then dst ips are returned, vice versa. If none is specified,
        all unique ips will be returned.

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            src_ip (optional[list(str), or single str]): src ip(s)

            dst_ip (optional[list(str), or single str]): dst ip(s),
                src_ip and dst_ip shouldn't be both specified

        Returns:
            list(str): unique ip addresses
        """
        return self.stat_ips(time_slot, src_ip, dst_ip).keys()

    def unique_protocols(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a unique set of protocols within the capture

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            src_ip (optional[list(str), or single str]): src ip(s)

            dst_ip (optional[list(str), or single str]): dst ip(s)

        Returns:
            list(str): unique protocols
        """
        return self.stat_protocols(time_slot, src_ip, dst_ip).keys()

    def unique_ports(self, time_slot=None, ip=None):
        """Get a unique set of ports within the capture

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            set(int): unique ports
        """
        return self.stat_ports(time_slot, ip).keys()

    def stat_macs(self, time_slot=None, ip=None):
        """Get a dict of MAC addresses with the freq it appears

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            ip (optional[list(str)]):

        Returns:
            dict{str->int}: mac addresses and the freq it appears
        """
        if ip is not None and not isinstance(ip, list):
            ip = [ip]
        return self.wrapper.stat_macs(timeslot_with_timestamps(time_slot), ip)

    def stat_ips(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a dict of ips and their freq

        It can be either src ip or dst ip. If src ip is specified,
        then dst ips are returned, vice versa. If none is specified,
        all unique ips will be returned.

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            src_ip (optional[list(str), or single str]): src ip(s).

            dst_ip (optional[list(str), or single str]): dst ip(s),
                src_ip and dst_ip shouldn't be both specified.

        Returns:
            dict{str->int}: ip addresses and freq.
        """
        if src_ip is not None and dst_ip is not None:
            raise Exception("src_ip and dst_ip shouldn't be both specified!")
        if src_ip is not None and not isinstance(src_ip, list):
            src_ip = [src_ip]
        if dst_ip is not None and not isinstance(dst_ip, list):
            dst_ip = [dst_ip]
        return self.wrapper.stat_ips(timeslot_with_timestamps(time_slot),
                                     src_ip, dst_ip)

    def stat_protocols(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a dict of protocols and freq

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp

            src_ip (optional[list(str), or single str]): src ip(s)

            dst_ip (optional[list(str), or single str]): dst ip(s)

        Returns:
            dict{str->int}: unique protocols
        """
        if src_ip is not None and dst_ip is not None:
            raise Exception("src_ip and dst_ip shouldn't be both specified!")
        if src_ip is not None and not isinstance(src_ip, list):
            src_ip = [src_ip]
        if dst_ip is not None and not isinstance(dst_ip, list):
            dst_ip = [dst_ip]
        return self.wrapper.stat_protocols(timeslot_with_timestamps(time_slot),
                                           src_ip, dst_ip)

    def stat_ports(self, time_slot=None, ip=None):
        """Get a dict of ports within the capture

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            dict{int->int}: unique ports
        """
        if ip is not None and not isinstance(ip, list):
            ip = [ip]
        return self.wrapper.stat_ports(timeslot_with_timestamps(time_slot), ip)


class HostSensor(Sensor):
    def __init__(self, backend='sys'):
        """ Init a host-based sensor

        Args:
            backend (str): either 'sys' or 'ossec'
        """
        super(Sensor, self).__init__()
        if backend == 'sys':
            if sys.platform == 'linux2':
                from ocd.host._linux import LinuxBackend
                self.backend = LinuxBackend()
            elif sys.platform == 'win32' or sys.platform == 'cygwin':
                from ocd.host._windows import WindowsBackend
                self.backend = WindowsBackend()
            elif sys.platform == 'darwin':
                from ocd.host._mac import MacBackend
                self.backend = MacBackend()
            else:
                raise NotImplementedError('System {} not supported!'
                                          .format(sys.platform))
        elif backend == 'ossec':
            from ocd.host._ossec import OssecBackend
            self.backend = OssecBackend()
        else:
            raise NotImplementedError('Backend not supported!')

    def load(self, **kwargs):
        """ Load the system log

        It loads log(s) from default location. If they are not in the
        default location, specify in **kwargs.

        TODO: document kwargs available for different backends

        Args:
            **kwargs: specifies custom config for sys logs
        """
        self.backend.load(**kwargs)

    def unique_logins(self, time_slot=None):
        """ Get the unique users logged in within a period

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            list(str): unique set of users
        """
        return self.stat_logins(time_slot).keys()

    def unique_logouts(self, time_slot=None):
        """ Get the unique users logged in within a period

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            list(str): unique set of users
        """
        return self.stat_logouts(time_slot).keys()

    def unique_authfailures(self, time_slot=None):
        """ Get the unique users failed in logging in within a period

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            list(str): unique set of users
        """
        return self.stat_authfailures(time_slot).keys()

    def stat_logins(self, time_slot=None):
        """ Get a dict of users and their login freq

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            dict(str->int): user vs how many times he successful logs in
        """
        return self.backend.stat_logins(solid_timeslot(time_slot))

    def stat_logouts(self, time_slot=None):
        """ Get a dict of users and their logout freq

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            dict(str->int): user vs how many times he logs out
        """
        return self.backend.stat_logouts(solid_timeslot(time_slot))

    def stat_authfailures(self, time_slot=None):
        """ Get a dict of users and their freq of authentication failure

        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

        Returns:
            dict(str->int): user vs how many times he failed to log in
        """
        return self.backend.stat_authfailures(solid_timeslot(time_slot))

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
        return self.backend.user_activities(user, solid_timeslot(time_slot))

    def cpu_usage(self):
        pass

    def mem_usage(self):
        pass

    def unique_apps(self):
        pass

    def processes(self):
        pass


class MotionSensor(Sensor):
    pass
