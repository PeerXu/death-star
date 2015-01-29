from gevent import monkey
monkey.patch_all()
import re
import gevent
from collections import namedtuple
import socket
import struct

class PacketBase(object):
    FIELDS = ()

    @classmethod
    def new(cls, _locals):
        return cls(**{k: _locals.get(k) for k in cls.FIELDS})

    @classmethod
    def _unpack_labels(cls, pkt, of):
        '''
        dns protocol: http://www.networksorcery.com/enp/protocol/dns.htm
        unpack dns packet: http://stackoverflow.com/questions/16977588/reading-dns-packets-in-python
        '''
        labels = []

        while True:
            length, = struct.unpack_from('!B', pkt, of)

            if (length & 0xc0) == 0xc0:
                pointer, = struct.unpack_from('!H', pkt, of)
                of += 2
                rest, _ = cls._unpack_labels(pkt, pointer & 0x3fff)
                return labels + rest, of

            of += 1

            if length == 0:
                return labels, of

            labels.append(*struct.unpack_from('!%ds' % length, pkt, of))
            of += length

    @classmethod
    def unpack_ipv4_address(cls, pkt, of):
        return '.'.join(map(str, struct.unpack('!4B', pkt[of:of+4]))), of

    @classmethod
    def _unpack_rdata(cls, pkt, of, type):
        if type == 5:
            rdata, _ = cls.unpack_labels(pkt, of)
        elif type == 1:
            rdata, _ = cls.unpack_ipv4_address(pkt, of)
        else:
            rdata, _ = None, of
        return rdata

    @classmethod
    def unpack_labels(cls, pkt, of):
        qname, of = cls._unpack_labels(pkt, of)
        return '.'.join(qname), of

DNS_HDR_FLDS = ('id', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra',
                'rcode', 'qdcount', 'ancount', 'nscount', 'arcount')
DNS_HDR_ST = struct.Struct('!6H')
class DNSHeader(namedtuple('DNSHeader', DNS_HDR_FLDS), PacketBase):
    FIELDS = DNS_HDR_FLDS

    @classmethod
    def unpack(cls, pkt):

        id, flag, qdcount, ancount, nscount, arcount = DNS_HDR_ST.unpack_from(pkt)
        qr = (flag & 0x8000) >> 15
        opcode = (flag & 0x7800) >> 11
        aa = (flag & 0x0400) >> 10
        tc = (flag & 0x0200) >> 9
        rd = (flag & 0x0100) >> 8
        ra = (flag & 0x0080) >> 7
        rcode = (flag & 0x000F)

        return cls.new(locals()), DNS_HDR_ST.size

DNS_QU_FLDS = ('qname', 'qtype', 'qclass')
DNS_QU_SEC_ST = struct.Struct('!2H')
class DNSQuestion(namedtuple('DNSQuestion', DNS_QU_FLDS), PacketBase):
    FIELDS = DNS_QU_FLDS

    @classmethod
    def unpack(cls, pkt, of, cnt=None):
        qus = []
        if cnt is None:
            cnt = 1

        for _ in range(cnt):
            qname, of = cls.unpack_labels(pkt, of)
            qtype, qclass = DNS_QU_SEC_ST.unpack_from(pkt, of)
            of += DNS_QU_SEC_ST.size

            qu = cls.new(locals())
            qus.append(qu)

        return qus, of

DNS_AN_FLDS = ('name', 'type', 'class_', 'ttl', 'rdlength', 'rdata')
DNS_AN_SEC_ST = struct.Struct('!2HIH')
class DNSAnswer(namedtuple('DNSResourceRecord', DNS_AN_FLDS),
                        PacketBase):
    FIELDS = DNS_AN_FLDS

    @classmethod
    def unpack(cls, pkt, of, cnt=None):
        ans = []
        if cnt is None:
            cnt = 1
        for _ in range(cnt):
            name, of = cls.unpack_labels(pkt, of)
            type, class_, ttl, rdlength = DNS_AN_SEC_ST.unpack_from(pkt, of)
            of += DNS_AN_SEC_ST.size
            rdata = cls._unpack_rdata(pkt, of, type)
            of += rdlength
            an = cls.new(locals())
            ans.append(an)

        return ans, of

DNS_REQ_FLDS = ('header', 'questions')
class DNSQuery(namedtuple('DNSQuery', DNS_REQ_FLDS),
                 PacketBase):
    FIELDS = DNS_REQ_FLDS

DNS_RPY_FLDS = ('header', 'questions', 'answers')
class DNSResponse(namedtuple('DNSResponse', DNS_RPY_FLDS),
               PacketBase):
    FIELDS = DNS_RPY_FLDS

def parse(pkt):
    header, offset = DNSHeader.unpack(pkt)
    questions, offset = DNSQuestion.unpack(pkt, offset, header.qdcount)

    if header.qr == 0:
        return DNSQuery.new(locals())

    answers, offset = DNSAnswer.unpack(pkt, offset, header.ancount)

    return DNSResponse.new(locals())

class DNSServer(object):
    def __init__(self, real_dns_addr=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def on_query(self, sip, sport, req):
        s = None
        try:
            print "[D] raw request: {}".format(repr(req))
            print "[D] request: {}".format(parse(req))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if s.sendto(req, ('114.114.114.114', 53)) == 0:
                print "[!] failed to query"
            else:
                reply = s.recv(2048)
                print "[D] raw reply: {}".format(repr(reply))
                print "[D] reply: {}".format(parse(reply))
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
