from gevent import monkey; monkey.patch_all()
from lxml.etree import HTML, Element, tostring
from gevent.pywsgi import WSGIServer
from gevent.pywsgi import WSGIHandler as _WSGIHandler
from httplib import HTTPConnection, IncompleteRead
import log

LOG = log.get_logger('web-proxy')

class HTTPHeader(dict):
    def __init__(self, *args, **kwargs):
        super(HTTPHeader, self).__init__(self, *args, **kwargs)
        for k in self.keys():
            self[k.lower()] = self.pop(k)

    def __getitem__(self, k):
        return self[k.lower().replace('_', '-')]

    def __setitem__(self, k, v):
        self[k.lower().replace('_', '-')] = v

def hijack(content):
    html = HTML(content)
    body = html.xpath('//body')[0]
    script = Element('script')
    script.text = 'alert(/hijacked/);'
    body.append(script)
    content = tostring(html)
    return content

def proxy_request_headers(env):
    headers = dict([(k.split('_', 1)[1].replace('_', '-'), env[k])
                    for k in env.keys()
                    if k.startswith('HTTP_')])
    # # disable gzip
    # if 'ACCEPT-ENCODING' in headers:
    #     headers.pop('ACCEPT-ENCODING')

    return headers

def application(env, start_response):
    req_hdrs = proxy_request_headers(env)
    host = req_hdrs['HOST']
    LOG.debug('host: %s', host)
    for k, v in req_hdrs.items():
        LOG.debug('>> %s: %s', k, v)
    conn = HTTPConnection(host)
    conn.request(env['REQUEST_METHOD'], env['PATH_INFO'], headers=req_hdrs)
    resp = conn.getresponse()

    _resp_hdrs = resp.getheaders()
    resp_hdrs = []
    for header, value in resp_hdrs:
        header = header.lower()
        if header == 'transfer-encoding' and value == 'thunked':
            continue

        resp_hdrs.append((header, value))

    start_response(' '.join([str(resp.status), resp.reason]), resp_hdrs)
    content = resp.read()
    # return hijack(content)
    return [content]

if __name__ == '__main__':
    httpd = WSGIServer(('', 80), application)
    httpd.serve_forever()
