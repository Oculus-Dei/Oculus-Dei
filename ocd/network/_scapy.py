

# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""

from scapy.all import *
import ocd.utils as utils

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
        return self.stat_ips(time_slot,src_ip,dst_ip).keys()


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
        packets = self.packets
        macs = []
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)
        if ip:
            packets = packets.filter(lambda p: IP in p and (p[IP].src in ip or p[IP].dst in ip)) 
        macs = map(lambda p: p[Ether].src, packets) + map(lambda p: p[Ether].dst, packets)
        return utils.get_frq_dict(macs)

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
        if src_ip and dst_ip:
            raise ValueError('src_ip and dst_ip should not be both specified')
        packets = self.packets.filter(lambda p: IP in p)
        ips = [];
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)
        if src_ip:
            packets = packets.filter(lambda p: p[IP].src in src_ip)
            ips = map(lambda p:p[IP].dst,packets)
        elif dst_ip:
            packets = packets.filter(lambda p: p[IP].dst in dst_ip)
            ips = map(lambda p:p[IP].src,packets)
        else:
            ips = map(lambda p:p[IP].src,packets) + map(lambda p:p[IP].dst,packets)
        return utils.get_frq_dict(ips)



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
