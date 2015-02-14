from gevent import monkey
monkey.patch_all()
import gevent
import socket
import re

import dns
import log

LOG = log.get_logger('dns-proxy')

class DNSServer(object):
    def __init__(self, host='0.0.0.0', port=53, nameserver='114.114.114.114'):
        self.sock = None
        self.host = host
        self.port = port
        self.nameserver = nameserver
        self.engine = MatchEngine('./resolv.txt', const={'current': '192.168.199.180'})

    def on_query(self, sip, sport, req):
        def lookup_remote_nameserver(que):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if s.sendto(dns.pack(que), (self.nameserver, 53)) == 0:
                LOG.error('failed to query')
                raise Exception('query failed')

            _resp = s.recv(2048)
            LOG.debug("raw response: {}".format(repr(_resp)))
            resp = dns.unpack(_resp)
            return resp
        # end lookup_remote_nameserver

        LOG.debug("raw query: {}".format(repr(req)))
        que = dns.unpack(req)
        LOG.debug("query: {}".format(que))
        host = self.engine.lookup(que.questions[0].qname)

        if not host:
            # reslov from remote nameserver.
            resp = lookup_remote_nameserver(que)
        else:
            qh = que.header
            qq = que.questions[0]
            resp = dns.DNSResponse(
                header=dns.DNSHeader(
                    id=qh.id, qr=1, opcode=qh.opcode,
                    aa=qh.aa, tc=qh.tc, rd=qh.rd, ra=qh.ra,
                    rcode=qh.rcode, qdcount=1, ancount=1, nscount=0, arcount=0),
                questions=que.questions,
                answers=[dns.DNSAnswer(
                    name=qq.qname, type=1, class_=1, ttl=255,
                    rdlength=4, rdata=host)])

        _resp = dns.pack(resp)
        LOG.debug("raw response: {}".format(repr(_resp)))
        LOG.debug("response: {}".format(resp))
        self.sock.sendto(_resp, (sip, sport))

    def serve_forever(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        try:
            while True:
                msg, (ip, port) = self.sock.recvfrom(2048)
                gevent.spawn(self.on_query, ip, port, msg)
        except KeyboardInterrupt:
            LOG.info("exit.")
        finally:
            self.sock.close()

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
        self.resolv_file = resolv_file
        self._const = const if isinstance(const, dict) else {}
        self._rules = self._read_rules_from_file(self.resolv_file)

    def lookup(self, domain):
        for domain_rule, host in self._rules.items():
            if domain_rule.match(domain):
                return host
        return None

    def reload(self):
        self._rules = self._read_rules_from_file(self.resolv_file)
