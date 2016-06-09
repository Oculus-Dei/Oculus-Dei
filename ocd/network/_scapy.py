# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""


class ScapyWrapper(object):
    def sniff(self, timeout=5):
        # TODO
        pass

    def unique_macs(self, time_slot=None, ip=None, hostname=None):
        """Get a unique set of MAC addresses within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[str]):
            hostname (optional[str]):

        Returns:
            set(str): mac addresses
        """
        # TODO
        pass

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
        # TODO
        pass

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
        # TODO
        pass

    def unique_ports(self, time_slot=None, ip=None):
        """Get a unique set of ports within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            set(int): unique ports
        """
        # TODO
        pass
