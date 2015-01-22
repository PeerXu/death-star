from gevent import monkey
monkey.patch_all()
import re
import gevent
from collections import namedtuple
import socket
import struct

DNS_HDR_FLDS = (
    'id', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra',
    'rcode', 'qdcount', 'ancount', 'nscount', 'arcount')
class DNSHeader(namedtuple('DNSHeader', DNS_HDR_FLDS)):
    @classmethod
    def unpack(cls, s):
        id, \
        flags, \
        qdcount, \
        ancount, \
        nscount, \
        arcount = struct.unpack('!HHHHHH', s[:12])

        qr = (flags & 0x8000) >> 15
        opcode = (flags & 0x7800) >> 11
        aa = (flags & 0x0400) >> 10
        tc = (flags & 0x0200) >> 9
        rd = (flags & 0x0100) >> 8
        ra = (flags & 0x0080) >> 7
        rcode = (flags & 0x000F)

        _locals = locals()
        kwargs = {k: _locals[k] for k in DNS_HDR_FLDS}
        return cls(**kwargs)

DNS_QUES_FLDS = (
    'name', 'qtype', 'qclass')
class DNSQuestion(namedtuple('DNSQuestion', DNS_QUES_FLDS)):
    @classmethod
    def unpack(cls, s):
        t = str(s)
        c = t[0]
        t = t[1:]
        ns = []
        while c != '\x00':
            n = ord(c)
            ns.append(t[:n])
            t = t[n:]
            c = t[0]
            t = t[1:]

        name = '.'.join(ns)
        qtype, qclass = struct.unpack('!HH', t[:4])
        _locals = locals()
        kwargs = {k: _locals[k] for k in DNS_QUES_FLDS}
        return cls(**kwargs)

DNS_RR_FLDS = (
    'name', 'qtype', 'qclass', 'ttl', 'rlen', 'rdata')
class DNSResourceRecord(namedtuple('DNSResourceRecord', DNS_RR_FLDS)):
    @classmethod
    def unpack(cls, s):
        name, \
        qtype, \
        qclass, \
        ttl, \
        rlen = struct.unpack('!IHHIH', s[:14])

        pass

class DNSServer(object):
    def __init__(self, real_dns_addr=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def on_query(self, sip, sport, req):
        s = None
        try:
            print "[D] raw request: {}".format(repr(req))
            print "[D] raw request header: {}".format(repr(req[:12]))
            print "[D] request header: {}".format(DNSHeader.unpack(req))
            print "[D] raw request body: {}".format(repr(req[12:]))
            print "[D] raw request question: {}".format(DNSQuestion.unpack(req[12:]))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if s.sendto(req, ('114.114.114.114', 53)) == 0:
                print "[!] failed to query"
            else:
                reply = s.recv(2048)
                print "[D] raw reply: {}".format(repr(reply))
                print "[D] raw reply header: {}".format(repr(reply[:12]))
                print "[D] reply header: {}".format(DNSHeader.unpack(reply))
                print "[D] raw reply body: {}".format(repr(reply[12:]))
                self._sock.sendto(reply, (sip, sport))
        finally:
            s and s.close()

    def serve_forever(self):
        self._sock.bind(('0.0.0.0', 53))
        try:
            while True:
                request, (ip, port) = self._sock.recvfrom(2048)
                gevent.spawn(self.on_query, ip, port, request)
        except KeyboardInterrupt:
            print "[X] exit."
        finally:
            self._sock.close()

class MatchEngine(object):
    def _read_rules_from_file(self, f):
        _rules = {}
        with open(f) as fr:
            rules = fr.read().split('\n')[:-1]
        for rule in rules:
            domain, host = rule.split()
            if host[0] == '<' and host[-1] == '>':
                host = self._const[host[1:-1]]
            _rules[re.compile(domain)] = host
        return _rules

    def __init__(self, resolv_file, const=None):
        self._const = const if isinstance(const, dict) else {}
        self._rules = self._read_rules_from_file(resolv_file)

    def lookup(self, domain):
        for domain_rule, host in self._rules.items():
            if domain_rule.match(domain):
                return host
        return None
