from collections import namedtuple
from ctypes import create_string_buffer
import socket
import struct

BUFSIZ = 4096

class DNSBuffer(object):
    def __init__(self):
        self.data = create_string_buffer(BUFSIZ)
        self.extra = create_string_buffer(BUFSIZ)
        self.dof = 0
        self.eof = 0

    @property
    def raw(self):
        return self.data.raw[:self.size]

    @property
    def size(self):
        return self.dof

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
    def unpack_ipvx_address(cls, pkt, of, ver):
        sz = 4 if ver == 4 else 16
        af = socket.AF_INET if ver == 4 else socket.AF_INET6
        raw = pkt[of:of+sz]
        return socket.inet_ntop(af, raw), of+sz

    @classmethod
    def unpack_ipv4_address(cls, pkt, of):
        return cls.unpack_ipvx_address(pkt, of, 4)

    @classmethod
    def unpack_ipv6_address(cls, pkt, of):
        return cls.unpack_ipvx_address(pkt, of, 6)

    @classmethod
    def _unpack_rdata(cls, pkt, of, type):
        if type == 5:
            rdata, _ = cls.unpack_labels(pkt, of)
        elif type == 1:
            rdata, _ = cls.unpack_ipv4_address(pkt, of)
        elif type == 28:
            rdata, _ = cls.unpack_ipv6_address(pkt, of)
        else:
            rdata, _ = '', of
        return rdata

    @classmethod
    def unpack_labels(cls, pkt, of):
        qname, of = cls._unpack_labels(pkt, of)
        return '.'.join(qname), of

    @classmethod
    def _pack_labels(cls, label):
        return ''.join(reduce(lambda xs, acc: xs+(chr(len(acc)), acc), label.split('.'), ())) + '\0'

    @classmethod
    def pack_labels(cls, label):
        packed = cls._pack_labels(label)
        return packed, len(packed)

    @classmethod
    def pack_ipvx_address(cls, ipvx_str, ver):
        sz = 4 if ver == 4 else 16
        af = socket.AF_INET if ver == 4 else socket.AF_INET6
        return socket.inet_pton(af, ipvx_str), sz

    @classmethod
    def pack_ipv4_address(cls, ipv4_str):
        return cls.pack_ipvx_address(ipv4_str, 4)

    @classmethod
    def pack_ipv6_address(cls, ipv6_str):
        return cls.pack_ipvx_address(ipv6_str, 6)

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

    def pack(self, buf):
        flags = (self.qr << 15) \
                + (self.opcode << 11) \
                + (self.aa << 10) \
                + (self.tc << 9) \
                + (self.rd << 8) \
                + (self.ra << 7) \
                + self.rcode
        DNS_HDR_ST.pack_into(buf.data, buf.dof, self.id, flags,
                             self.qdcount, self.ancount, self.nscount, self.arcount)
        buf.dof += DNS_HDR_ST.size
        return buf

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

    def pack(self, buf):
        packed_labels = self._pack_labels(self.qname)
        packed_labels_len = len(packed_labels)
        struct.pack_into('!{}c'.format(packed_labels_len), buf.data, buf.dof, *packed_labels)
        buf.dof += packed_labels_len
        DNS_QU_SEC_ST.pack_into(buf.data, buf.dof, self.qtype, self.qclass)
        buf.dof += DNS_QU_SEC_ST.size
        return buf

DNS_AN_FLDS = ('name', 'type', 'class_', 'ttl', 'rdlength', 'rdata')
DNS_AN_SEC_ST = struct.Struct('!2HIH')
class DNSAnswer(namedtuple('DNSAnswer', DNS_AN_FLDS), PacketBase):
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

    def pack_rdata(self):
        if self.type == 5:
            rdata, rlength = self.pack_labels(self.rdata)
        elif self.type == 1:
            rdata, rlength = self.pack_ipv4_address(self.rdata)
        elif self.type == 28:
            rdata, rlength = self.pack_ipv6_address(self.rdata)
        else:
            rdata, rlength = '', 1
        return rdata, rlength

    def pack(self, buf):
        name, of = self.pack_labels(self.name)
        struct.pack_into('!{}c'.format(of), buf.data, buf.dof, *name)
        buf.dof += of
        packed, rlength = self.pack_rdata()
        DNS_AN_SEC_ST.pack_into(buf.data, buf.dof, self.type, self.class_, self.ttl, rlength)
        buf.dof += DNS_AN_SEC_ST.size
        struct.pack_into('!{}c'.format(rlength), buf.data, buf.dof, *packed)
        buf.dof += rlength
        return buf

DNS_REQ_FLDS = ('header', 'questions')
class DNSQuery(namedtuple('DNSQuery', DNS_REQ_FLDS), PacketBase):
    FIELDS = DNS_REQ_FLDS

    def pack(self, buf):
        self.header.pack(buf)
        map(lambda que: que.pack(buf), self.questions)
        return buf

DNS_RPY_FLDS = ('header', 'questions', 'answers')
class DNSResponse(namedtuple('DNSResponse', DNS_RPY_FLDS), PacketBase):
    FIELDS = DNS_RPY_FLDS

    def pack(self, buf):
        self.header.pack(buf)
        map(lambda que: que.pack(buf), self.questions)
        map(lambda ans: ans.pack(buf), self.answers)

def unpack(raw):
    header, offset = DNSHeader.unpack(raw)
    questions, offset = DNSQuestion.unpack(raw, offset, header.qdcount)

    if header.qr == 0:
        return DNSQuery.new(locals())

    answers, offset = DNSAnswer.unpack(raw, offset, header.ancount)

    return DNSResponse.new(locals())

def pack(pkt):
    buf = DNSBuffer()
    pkt.pack(buf)
    return buf.raw
