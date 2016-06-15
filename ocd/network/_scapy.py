

# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""

from scapy.all import *

class ScapyWrapper(object):
    def __init__(self):
        self.packets = None

    def sniff(self, interface,timeout=5):
        self.packets = sniff(iface=interface,timeout=timeout);

    def load(self, capfile):
        self.packets = rdpcap(capfile);

    def unique_macs(self, time_slot=None, ip=None):
        """Get a unique set of MAC addresses within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str)]):

        Returns:
            set(str): mac addresses
        """
        return self.stat_macs(time_slot,ip).keys()

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
        packets = self.packets.filter(lambda p: IP in p)
        ips = set();
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)


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
        # TODO@xiaolong
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
        # TODO@xiaolong
        pass

    def stat_macs(self, time_slot=None, ip=None):
        """Get a dict of MAC addresses with the freq it appears

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str)]):

        Returns:
            dict{str->int}: mac addresses and the freq it appears
        """
        if not self.packets:
            return {}
        else:
            packets = self.packets
        macs = []
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)
        if ip:
            packets = packets.filter(lambda p: IP in p and (p[IP].src == ip or p[IP].dst == ip)) 
        macs = map(lambda p: p[Ether].src, packets) + map(lambda p: p[Ether].dst, packets)
        mac_dict = {}
        for mac in macs:
            if mac in mac_dict:
                mac_dict[mac] += 1
            else:
                mac_dict[mac] = 1
        return mac_dict

    def stat_ips(self, time_slot=None, src_ip=None, dst_ip=None):
        """Get a dict of ips and their freq

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
            dict{str->int}: ip addresses and freq
        """
        if not self.packets:
            return {}
        else:
            packets = self.packets
        ips = []
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)
        if src_ip and dst_ip:
            


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
        # TODO@manga
        pass

    def stat_ports(self, time_slot=None, ip=None):
        """Get a dict of ports within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            dict{int->int}: unique ports
        """
        # TODO@manga
        pass
