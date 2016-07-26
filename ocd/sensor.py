# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Main API for sensors
"""

import sys
import inspect

from utils import (solid_timeslot,
                   timeslot_with_timestamps,
                   sys_not_supported)


class Sensor(object):
    @classmethod
    def get_supported_backends(cls):
        """ Return a list of supported backends. """
        raise NotImplementedError()

    @classmethod
    def get_installed_backends(cls):
        """ Return a dict of installed backends, where key is str, val is class. """
        raise NotImplementedError()

    def __init__(self, backend):
        """ Init a sensor

        Args:
            backend (str): backend sensor type
        """
        self.backend_str = backend
        backends = self.get_installed_backends()
        if backend in backends:
            self.backend = backends[backend]()
        else:
            raise NotImplementedError('Backend not supported!')

    def get_features(self, name=None):
        """ get a dict of available features, or the spec of a feature.

        If name is None, the entire features are returned.
        If name is str, the spec of that feature is returned.

        Args:
            name: The feature name.

        Returns:
            list or str.
        """
        members = inspect.getmembers(self, inspect.ismethod)
        features = {m[0]: inspect.getdoc(m[1]) for m in members}
        if name is None:
            return features.keys()
        elif name in features:
            return features[name]
        else:
            raise NotImplementedError("Feature not supported!")

    def __repr__(self):
        return "<{} backend='{}'>".format(self.__class__.__name__,
                                          self.backend_str)


class NetworkSensor(Sensor):
    """ Network sensor for packet analysis """

    @classmethod
    def get_supported_backends(cls):
        """ Get a list of supported backends. """
        return ['pyshark', 'scapy']

    @classmethod
    def get_installed_backends(cls):
        """ Get a dict of installed backends, mapping str to cls. """
        backends = {}
        try:
            from network._pyshark import PysharkWrapper
            backends['pyshark'] = PysharkWrapper
        except ImportError:
            pass
        try:
            from network._scapy import ScapyWrapper
            backends['scapy'] = ScapyWrapper
        except ImportError:
            pass
        return backends

    def __init__(self, backend='pyshark'):
        """ Init a network sensor

        Args:
             backend (str): either 'pyshark' or 'scapy'
        """
        super(NetworkSensor, self).__init__(backend)

    def sniff(self, interface, timeout=10, output_file=None):
        """ Sniff from an interface for a period of time

        Args:
            interface (str): the interface to sniff from, e.g. en0

            timeout (optional[int]): time to sniff

            output_file (optional[str]): if specified,
                packets will be saved to this location.
        """
        self.backend.sniff(interface, timeout, output_file)

    def load(self, capfile):
        """Load a capture file. Backend could change accordingly.

        Args:
            capfile: capture file
        """
        self.backend.load(capfile)

    def http_req_urls(self, time_slot=None, ip=None, method=None):
        """ Get a list of urls to which the host sends http requests.

        Args:
            time_slot (optional[tuple(datetime)]): tuple of datetime
                specifying start and end time within which to be filtered

            ip (optional[list(str) or str]): ips within which to be filtered

            method (optional[list(str) or str]): http request method

        Returns:
            list(str): list of urls
        """
        if method is not None:
            if not isinstance(method, list):
                method = [method]
            method = map(lambda m: m.upper(), method)
        if ip is not None:
            if not isinstance(ip, list):
                ip = [ip]
        return self.backend.http_req_urls(time_slot, ip, method)

    def stat_http_resp_ips(self, time_slot=None, content_type=None):
        """ Stat ips from which the host receives http responses.

        Args:
            time_slot (optional[tuple(datetime)]): tuple of datetime
                specifying start and end time within which to be filtered

            content_type (optional[list[str] or str]):
                content type to be filtered.

        Returns:
            dict{str->int}: ips and freq's
        """
        if content_type is not None:
            if not isinstance(content_type, list):
                content_type = [content_type]
            content_type = map(lambda c: c.lower(), content_type)
        return self.backend.stat_http_resp_ips(timeslot_with_timestamps(time_slot),
                                               content_type)

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
        return self.backend.stat_macs(timeslot_with_timestamps(time_slot), ip)

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
        return self.backend.stat_ips(timeslot_with_timestamps(time_slot),
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
        return self.backend.stat_protocols(timeslot_with_timestamps(time_slot),
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
        return self.backend.stat_ports(timeslot_with_timestamps(time_slot), ip)


class AuthSensor(Sensor):
    @classmethod
    def get_supported_backends(cls):
        """ Get a list of supported backends. """
        return ['sys']

    @classmethod
    def get_installed_backends(cls):
        """ Get a dict of installed backends, mapping str to cls. """
        backends = {}
        if sys.platform == 'linux2':
            from ocd.auth._linux import LinuxBackend
            backends['sys'] = LinuxBackend
        elif sys.platform == 'win32' or sys.platform == 'cygwin':
            from ocd.auth._windows import WindowsBackend
            backends['sys'] = WindowsBackend
        elif sys.platform == 'darwin':
            from ocd.auth._mac import MacBackend
            backends['sys'] = MacBackend
        else:
            backends['sys'] = sys_not_supported
        return backends

    def __init__(self, backend='sys'):
        """ Init an auth sensor.

        Args:
            backend (str): only 'sys' is supported now.
        """
        super(AuthSensor, self).__init__(backend)

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


class FileSensor(Sensor):
    @classmethod
    def get_supported_backends(cls):
        """ Get a list of supported backends. """
        return ['sys']

    @classmethod
    def get_installed_backends(cls):
        """ Get a dict of installed backends, mapping str to cls. """
        backends = {}
        if sys.platform == 'darwin':
            from ocd.file._mac import MacBackend
            backends['sys'] = MacBackend
        else:
            backends['sys'] = sys_not_supported
        return backends

    def __init__(self, backend='sys'):
        """ Init a file sensor
        Args:
            backend (str): only 'sys' is supported
        """
        super(FileSensor, self).__init__(backend)

    def snoop(self, timeout=10):
        """ Snoop open's for a while

        Args:
            timeout (optional[int]): how long to snoop.
        """
        self.backend.snoop(timeout)

    def unique_users(self, time_slot=None, cmd=None, fpath=None):
        """ Unique api for stat_users. See stat_users for detail. """
        return self.stat_users(time_slot, cmd, fpath).keys()

    def unique_cmds(self, time_slot=None, user=None, fpath=None):
        """ Unique api for stat_cmds. See stat_cmds for detail. """
        return self.stat_cmds(time_slot, user, fpath).keys()

    def unique_fpaths(self, time_slot=None, user=None, cmd=None):
        """ Unique api for stat_fpaths. See stat_fpaths for detail. """
        return self.stat_fpaths(time_slot, user, cmd).keys()

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
        return self.backend.stat_fpaths(time_slot, user, cmd)

    def user_activities(self, user, time_slot=None, cmd=None, fpath=None):
        """ Give a list of activities with regard to a user. Sorted by time.

        Args:
            user (optional[list[str]]): the user to look for.

            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            cmd (optional[list[str]]): a list of cmds within which
                to be filtered. Could also be a single str.

            fpath (optional[list[str]]): a list of files within which
                to be filtered. Could also be a single str.

        Returns:
            list[{'time': xxx, 'cmd': xxx, 'fpath': xxx}]
        """
        return self.backend.user_activities(user, time_slot, cmd, fpath)

    def cmd_activities(self, cmd, time_slot=None, user=None, fpath=None):
        """ Give a list of activities with regard to a cmd. Sorted by time.

        Args:
            cmd (optional[list[str]]): the cmd to look for.

            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime

            user (optional[list[str]]): a list of users within which
                to be filtered. Could also be a single str.

            fpath (optional[list[str]]): a list of files within which
                to be filtered. Could also be a single str.

        Returns:
            list[{'time': xxx, 'user': xxx, 'fpath': xxx}]
        """
        return self.backend.cmd_activities(cmd, time_slot, user, fpath)

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
            list[{'time': xxx, 'user': xxx, 'cmd': xxx}]
        """
        return self.backend.fpath_activities(fpath, time_slot, user, cmd)
