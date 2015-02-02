from gevent import monkey
monkey.patch_all()
import gevent
import socket
import re

import dns

class DNSServer(object):
    def __init__(self, real_dns_addr=None):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def on_query(self, sip, sport, req):
        s = None
        try:
            print "[D] raw query: {}".format(repr(req))
            que = dns.unpack(req)
            print "[D] query: {}".format(que)
            print "[D] raw query with packed: {}".format(repr(dns.pack(que)))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if s.sendto(req, ('114.114.114.114', 53)) == 0:
                print "[!] failed to query"
            else:
                resp = s.recv(2048)
                print "[D] raw response: {}".format(repr(resp))
                print "[D] response: {}".format(dns.unpack(resp))
                self._sock.sendto(resp, (sip, sport))
        finally:
            s and s.close()

    def serve_forever(self):
        self._sock.bind(('0.0.0.0', 53))
        try:
            while True:
                msg, (ip, port) = self._sock.recvfrom(2048)
                gevent.spawn(self.on_query, ip, port, msg)
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
