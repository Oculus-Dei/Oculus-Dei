# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""

__author__ = 'misaka-10032 (longqic@andrew.cmu.edu)'


class Sensor(object):
    def __init__(self, backend):
        pass


class NetworkSensor(Sensor):
    def __init__(self, backend='pyshark'):
        """
        Args:
            backend (str): either 'pyshark' or 'scapy'
        """
        # TODO: add cap file in constructor
        if backend == 'pyshark':
            from network._pyshark import PysharkWrapper
            self.wrapper = PysharkWrapper()
        elif backend == 'scapy':
            from network._scapy import ScappyWrapper
            self.wrapper = ScappyWrapper()
        else:
            raise NotImplementedError('Backend not supported!')

    def sniff(self, interface, timeout=5):
        """Sniff from an interface for a period of time

        Args:
            interface (str): the interface to sniff from, e.g. en0
            timeout (optional[int]): time to sniff
        :return:
        """
        self.wrapper.sniff(interface, timeout)

    def load(self, capfile):
        """Load a capture file. Backend could change accordingly.
        Args:
            capfile: capture file
        """
        # TODO: check file type
        self.wrapper.load(capfile)

    def unique_macs(self, time_slot=None, ip=None):
        """Get a unique set of MAC addresses within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str)]):

        Returns:
            set(str): mac addresses
        """
        if ip is not None and not isinstance(ip, list):
            ip = [ip]
        return self.wrapper.unique_macs(time_slot, ip)

    def unique_ips(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a unique set of ips within the capture

        It can be either src ip or dst ip. If src ip is specified,
        then dst ips are returned, vice versa. If none is specified,
        all unique ips will be returned.

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            src_ip (optional[list(str), or single str]): src ip(s)
            dst_ip (optional[list(str), or single str]): dst ip(s),
                src_ip and dst_ip shouldn't be both specified

        Returns:
            set(str): unique ip addresses
        """
        if src_ip is not None and dst_ip is not None:
            raise Exception("src_ip and dst_ip shouldn't be both specified!")
        if src_ip is not None and not isinstance(src_ip, list):
            src_ip = [src_ip]
        if dst_ip is not None and not isinstance(dst_ip, list):
            dst_ip = [dst_ip]
        return self.wrapper.unique_ips(time_slot, src_ip, dst_ip)

    def unique_protocols(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a unique set of protocols within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            src_ip (optional[list(str), or single str]): src ip(s)
            dst_ip (optional[list(str), or single str]): dst ip(s)

        Returns:
            set(str): unique protocols
        """
        if src_ip is not None and dst_ip is not None:
            raise Exception("src_ip and dst_ip shouldn't be both specified!")
        if src_ip is not None and not isinstance(src_ip, list):
            src_ip = [src_ip]
        if dst_ip is not None and not isinstance(dst_ip, list):
            dst_ip = [dst_ip]
        return self.wrapper.unique_protocols(time_slot, src_ip, dst_ip)

    def unique_ports(self, time_slot=None, ip=None):
        """Get a unique set of ports within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            set(int): unique ports
        """
        if ip is not None and not isinstance(ip, list):
            ip = [ip]
        return self.wrapper.unique_ports(time_slot, ip)


class MotionSensor(Sensor):
    pass
