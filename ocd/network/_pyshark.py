# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).
All rights reserved.

Wrapper for pyshark.
"""

import pyshark
import ocd.utils as utils


class PysharkWrapper(object):
    def __init__(self):
        self.cap = None

    def sniff(self, interface, timeout=5, output_file=None):
        self.cap = pyshark.LiveCapture(interface=interface, output_file=output_file)
        self.cap.sniff(timeout=timeout)
        self.packets = self.cap._packets

    def load(self, capfile):
        self.cap = pyshark.FileCapture(capfile)
        self.cap.load_packets()
        self.packets = self.cap._packets

    def http_req_urls(self, time_slot=None, ip=None, method=None):
        def _filter(p):
            if 'http' not in p:
                return False
            if 'request' not in p.http.field_names:
                return False
            if time_slot is not None:
                start, end = time_slot
                if float(p.sniff_timestamp) < start or \
                   float(p.sniff_timestamp) >= end:
                    return False
            if ip is not None:
                if p.ip.dst not in ip:
                    return False
            if method is not None:
                if p.http.request_method.upper() not in method:
                    return False
            return True
        packets = self.packets
        packets = filter(_filter, packets)
        urls = map(lambda p: p.http.request_full_uri, packets)
        return urls

    def stat_http_resp_ips(self, time_slot=None, content_type=None):
        def _filter(p):
            if 'http' not in p:
                return False
            if 'response' not in p.http.field_names:
                return False
            if time_slot is not None:
                start, end = time_slot
                if float(p.sniff_timestamp) < start or \
                   float(p.sniff_timestamp) >= end:
                    return False
            if content_type is not None and 'content_type' in p.http.field_names:
                if p.http.content_type.lower() not in content_type:
                    return False
            return True
        packets = self.packets
        packets = filter(_filter, packets)
        ips = {}
        for p in packets:
            utils.dict_acc(ips, {p.ip.src: 1})
        return ips

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
        if time_slot:
            start, end = time_slot
            packets = filter(lambda p: start <= float(p.sniff_timestamp) < end,
                             packets)
        macs = {}
        for p in packets:
            if 'ip' in p:
                if ip and p.ip.src in ip:
                    utils.dict_acc(macs, {p.eth.src: 1})
                if ip and p.ip.dst in ip:
                    utils.dict_acc(macs, {p.eth.dst: 1})
                if not ip:
                    utils.dict_acc(macs, {
                        p.eth.src: 1,
                        p.eth.dst: 1,
                    })
        return macs

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
        packets = self.packets
        ips = {}
        packets = filter(lambda p: 'ip' in p, packets)
        if time_slot:
            start, end = time_slot
            packets = filter(lambda p:
                             start <= float(p.sniff_timestamp) < end, packets)

        if src_ip:
            for p in packets:
                if 'ip' in p and p.ip.src in src_ip:
                    utils.dict_acc(ips, {p.ip.dst: 1})
        if dst_ip:
            for p in packets:
                if 'ip' in p and p.ip.dst in dst_ip:
                    utils.dict_acc(ips, {p.ip.src: 1})

        if not src_ip and not dst_ip:
            for p in packets:
                if 'ip' in p:
                    utils.dict_acc(ips, {
                        p.ip.src: 1,
                        p.ip.dst: 1,
                    })

        return ips

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
        packets = self.packets
        protocols = {}
        if time_slot:
            start, end = time_slot
            packets = filter(lambda p:
                             start <= float(p.sniff_timestamp) < end, packets)

        if src_ip:
            for p in packets:
                if 'ip' in p and p.ip.src in src_ip:
                    utils.dict_acc(protocols, {p.frame_info.protocols: 1})
        if dst_ip:
            for p in packets:
                if 'ip' in p and p.ip.dst in dst_ip:
                    utils.dict_acc(protocols, {p.frame_info.protocols: 1})

        if not src_ip and not dst_ip:
            for p in packets:
                if 'ip' in p:
                    utils.dict_acc(protocols, {
                        p.frame_info.protocols: 1,
                    })

        return protocols

    def stat_ports(self, time_slot=None, ip=None):
        """Get a dict of ports within the capture

        Args:
            time_slot (optional[tuple]): a tuple of two specifying the
                start and end time in the format of timestamp
            ip (optional[list(str), or single str]): the corresponding ip(s)

        Returns:
            dict{int->int}: unique ports
        """
        packets = self.packets
        ports = {}
        if time_slot:
            start, end = time_slot
            packets = filter(lambda p:
                             start <= float(p.sniff_timestamp) < end, packets)
        if ip:
            packets = filter(lambda p: 'ip' in p, packets)
            p_src = filter(lambda p: p.ip.src in ip, packets)
            for p in p_src:    
                if 'tcp' in p:
                    utils.dict_acc(ports, {p.tcp.port: 1})
                elif 'udp' in p:
                    utils.dict_acc(ports, {p.udp.port: 1})
            p_dst = filter(lambda p: p.ip.dst in ip, packets)
            for p in p_dst:            
                if 'tcp' in p:
                    utils.dict_acc(ports, {p.tcp.port: 1})
                elif 'udp' in p:
                    utils.dict_acc(ports, {p.udp.port: 1})
        else:
            for p in packets:
                if 'tcp' in p:
                    utils.dict_acc(ports, {p.tcp.port: 1})
                elif 'udp' in p:
                    utils.dict_acc(ports, {p.udp.port: 1})

        return ports
