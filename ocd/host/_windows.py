# encoding: utf-8
"""
Created by misaka-10032 (longqic@andrew.cmu.edu).

Windows backend for host-based sensor
"""
from lxml import etree
#import xml.etree.cElementTree as etree

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from datetime import datetime
from ocd.utils import dict_acc, solid_timeslot
DEFAULT_SYSLOG = "c:/Windows/System32/winevt/Logs/Security.evtx"
EVENT_ID = {'login':4624,'authfail':4625,'logout':4647}

def to_lxml(record_xml):
    """
    @type record: Record
    """
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
                         record_xml)


def xml_records(filename):
    """
    If the second return value is not None, then it is an
      Exception encountered during parsing.  The first return value
      will be the XML string.

    @type filename str
    @rtype: generator of (etree.Element or str), (None or Exception)
    """
    with Evtx(filename) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield to_lxml(xml), None
            except etree.XMLSyntaxError as e:
                yield xml, e
def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    """
    @type node: etree.Element
    @type tag: str
    @type ns: str
    """
    return node.find("%s%s" % (ns, tag))

class WindowsBackend(object):
    def __init__(self):
        self.logins = []
        self.logouts = []
        self.authf =[]
        #self.load()

    def load(self, **kwargs):
        """ Load the system log

        It loads log(s) from default location. If they are not in the
        default location, specify in **kwargs.

        TODO: document kwargs necessary for log location

        Args:
            **kwargs: specifies custom config for sys logs
        """
        syslog_evtx = DEFAULT_SYSLOG
        if "evtx" in kwargs:
            syslog_evtx = kwargs["evtx"]
        for node, err in xml_records(syslog_evtx):
            if err is not None:
                continue
            temp = {}
            sys = get_child(node, "System")
            time = get_child(sys,"TimeCreated")
            tfmt = '%Y-%m-%d %H:%M:%S'
            temp['Time'] = datetime.strptime(str(time.get('SystemTime'))[:-7], tfmt)
            if EVENT_ID['login'] == int(get_child(sys, "EventID").text):
                data = get_child(node,"EventData")
                for n in data:
                    #print type(n.attrib['Name'])
                    if n.attrib['Name'] == 'TargetUserName':
                        temp['TargetUserName'] = str(n.text)
                    if n.attrib['Name'] == 'LogonProcessName':
                        temp['LogonProcessName'] = str(n.text)
                    if n.attrib['Name'] == 'IpAddress':
                        temp['IpAddress'] = str(n.text)
                if temp['LogonProcessName'].strip() == 'User32':
                    self.logins.append({
                        'user':     temp['TargetUserName'],
                        'ip':       temp['IpAddress'],
                        'time_in':  temp['Time'],
                    })
            if EVENT_ID['logout'] == int(get_child(sys, "EventID").text):
                data = get_child(node,"EventData")
                for n in data:
                    if n.attrib['Name'] == 'TargetUserName':
                        temp['TargetUserName'] = str(n.text)
                        break
                self.logouts.append({
                        'user':     temp['TargetUserName'],
                        'ip':       None,
                        'time_out':  temp['Time'],
                    })
            if EVENT_ID['authfail'] == int(get_child(sys, "EventID").text):
                data = get_child(node,"EventData")
                for n in data:
                    if n.attrib['Name'] == 'TargetUserName':
                        temp['TargetUserName'] = str(n.text)
                    if n.attrib['Name'] == 'IpAddress':
                        temp['IpAddress'] = str(n.text)
                self.authf.append({
                    'user':     temp['TargetUserName'],
                    'ip':       temp['IpAddress'],
                    'time_in':  temp['Time'],
                })

    def stat_logins(self, time_slot=None):
        """ Get a dict of users and their login freq
        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he successful logs in
        """
        r = {}
        start, end = time_slot
        for login in self.logins:
            if start <= login['time_in'] < end:
                dict_acc(r, {login['user']: 1})
        return r

    def stat_logouts(self, time_slot=None):
        """ Get a dict of users and their logout freq
        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he logs out
        """
        r = {}
        start, end = time_slot
        for logout in self.logouts:
            if start <= logout['time_out'] < end:
                dict_acc(r, {logout['user']: 1})
        return r

    def stat_authfailures(self, time_slot=None):
        """ Get a dict of users and their freq of authentication failure
        Args:
            time_slot (optional[tuple(datetime)]): a tuple of two
                specifying the start and end time as datetime
        Returns:
            dict(str->int): user vs how many times he failed to log in
        """
        r = {}
        start, end = time_slot
        for authfailure in self.authf:
            if start <= authfailure['time_in'] < end:
                dict_acc(r, {authfailure['user']: 1})
        return r

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
        activities = []
        start, end = time_slot
        for login in self.logins:
            if login['user'] != user:
                continue
            if start <= login['time_in'] < end:
                activities.append({
                    'activity': 'login',
                    'ip': login['ip'],
                    'time': login['time_in']
                })
        for logout in self.logouts:
            if logout['user'] != user:
                continue
            if start <= logout['time_out'] < end:
                activities.append({
                    'activity': 'logout',
                    'ip': logout['ip'],
                    'time': logout['time_out']
                })
        for authfailure in self.authf:
            if authfailure['user'] != user:
                continue
            if start <= authfailure['time_in'] < end:
                activities.append({
                    'activity': 'authfailure',
                    'ip': authfailure['ip'],
                    'time': authfailure['time_in']
                })
        return sorted(activities, key=lambda a: a['time'])
