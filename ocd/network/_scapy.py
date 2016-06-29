# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

TODO: purpose
"""

from collections import Counter
from scapy.all import Ether
import scapy.all as scp
import ocd.utils as utils


class ScapyWrapper(object):
    def __init__(self):
        self.packets = None

    def sniff(self, interface, timeout=5):
        self.packets = scp.sniff(iface=interface, timeout=timeout)

    def load(self, capfile):
        self.packets = scp.rdpcap(capfile)

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
            packets = packets.filter(lambda p: p.haslayer('IP') and (p['IP'].src in ip or p['IP'].dst in ip))

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
        packets = self.packets.filter(lambda p: p.haslayer('IP'))
        ips = []
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time <= end)

        if src_ip:
            packets = packets.filter(lambda p: p['IP'].src in src_ip)
            ips = map(lambda p: p['IP'].dst, packets)
        elif dst_ip:
            packets = packets.filter(lambda p: p['IP'].dst in dst_ip)
            ips = map(lambda p: p['IP'].src, packets)
        else:
            ips = map(lambda p: p['IP'].src, packets) + map(lambda p: p['IP'].dst, packets)
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
        if not self.packets:
            return
        else:
            packets = self.packets
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time < end)

        if dst_ip:
            packets = packets.filter(lambda p: p.haslayer('IP') and p['IP'].dst in dst_ip)

        if src_ip:
            packets = packets.filter(lambda p: p.haslayer('IP') and p['IP'].src in src_ip)

        protocols = packets.__repr__()
        protocols_list = protocols.split()

        packets.show()
        protocols_dict = {}
        for x in range(2, 6):
            index = protocols_list[x].index(':')
            key = protocols_list[x][:index]
            count = protocols_list[x][index + 1:]
            if count[len(count) - 1] == '>':
                count = count[:len(count) - 2]
            else:
                count_int = int(count)
            protocols_dict[key] = count_int

        return protocols_dict

    def stat_ports(self, time_slot=None, ip=None):
        """Get a dict of ports within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            dict{int->int}: unique ports
        """
        if not self.packets:
            return
        else:
            packets = self.packets
        if time_slot:
            start, end = time_slot
            packets = packets.filter(lambda p: start <= p.time < end)

        if ip:
            packets_dst = packets.filter(lambda p: p.haslayer('IP') and p['IP'].dst in ip)
            packets_src = packets.filter(lambda p: p.haslayer('IP') and p['IP'].src in ip)
        else:
            packets_dst = packets_src = packets

        # src == ip
        tcp_packets = packets_src.filter(lambda p: p.haslayer('TCP'))
        udp_packets = packets_src.filter(lambda p: p.haslayer('UDP'))

        tcp_packets.show()

        ports_src = map(lambda p: p['TCP'].sport, tcp_packets) + map(lambda p: p['UDP'].sport, udp_packets)

        print ports_src

        # dst == ip

        tcp_packets = packets_dst.filter(lambda p: p.haslayer('TCP'))
        udp_packets = packets_dst.filter(lambda p: p.haslayer('UDP'))

        tcp_packets.show()

        ports_dst = map(lambda p: p['TCP'].sport, tcp_packets) + map(lambda p: p['UDP'].sport, udp_packets)

        if ip:
            ports = ports_dst + ports_src
            result = dict(Counter(ports))
        else:
            result = dict(Counter(ports_dst))

        return result
