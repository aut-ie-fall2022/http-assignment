#!/usr/bin/env python3
import argparse
import json
import requests
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from jwcrypto import jwt, jwk

hostname = '127.0.0.1:8081'
sym_key = ''


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def send_request(self, request_method, body=True):
        sent = False
        try:
            url = 'http://{}{}'.format(hostname, self.path)
            request_body = None
            content_len = int(self.headers.get('content-length', 0))
            request_body = self.rfile.read(content_len)
            print()
            if self.check_authentication():
                self.headers.replace_header("Host", hostname)
                print("Request Header")
                print(self.headers)
                resp = requests.request(request_method, url, data=request_body, headers=self.headers, verify=False)
                sent = True

                self.log_request(resp.status_code)
                self.send_response_only(resp.status_code, None)
                self.send_resp_headers(resp)

                if body:
                    self.wfile.write(resp.content)
            else:
                self.send_error(401, 'Unauthorized')
                sent = True
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def do_HEAD(self):
        self.send_request('HEAD', body=False)

    def do_GET(self, body=True):
        self.send_request('GET', body)

    def do_POST(self, body=True):
        self.send_request('POST', body)

    def do_DELETE(self, body=True):
        self.send_request('DELETE', body)

    def do_PUT(self, body=True):
        self.send_request('PUT', body)

    def do_PATCH(self, body=True):
        self.send_request('PATCH', body)

    def check_authentication(self):
        auth = self.headers.get('Authorization', None)
        if auth is None:
            print("No Authentication")
            return False

        auth_list = auth.split(' ')
        if len(auth_list) != 2 or auth_list[0] != 'Bearer':
            print("Bad Authorization Header")
            return False
        try:
            encrypted_token = jwt.JWT(key=sym_key, jwt=auth_list[1])
            simple_token = jwt.JWT(key=sym_key, jwt=encrypted_token.claims)
        except Exception as e:
            print("Bad JWT")
            return False
        if simple_token.serialize() != encrypted_token.claims:
            return False
        del self.headers['Authorization']
        try:
            exp_time = json.loads(simple_token.claims)['exp']
        except KeyError:
            print("No Expiry Time!")
            return False

        if exp_time < int(time.time()):
            print("Token Is Expired")
            return False

        return True

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding',
                           'content-length', 'Content-Length']:
                print(key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', str(len(resp.content)))
        self.end_headers()


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=80,
                        help='serve HTTP requests on specified port (default: 80)')
    parser.add_argument('--hostname', dest='hostname', type=str, default='127.0.0.1:8081',
                        help='hostname to be processd (default: 127.0.0.1:8081)')
    args = parser.parse_args(argv)
    return args


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    global hostname, sym_key
    args = parse_args(argv)
    hostname = args.hostname
    sym_key = jwk.JWK.generate(kty='oct', size=256)
    cur_time = int(time.time())
    token = jwt.JWT(header={'alg': 'HS256'},
                    claims={'iss': '9731707', 'sub': '1234567890', 'aud': '9733048', 'exp': cur_time+120})
    token.make_signed_token(sym_key)

    eToken = jwt.JWT(header={"alg": "A256KW", "enc": "A256CBC-HS512"},
                     claims=token.serialize())
    eToken.make_encrypted_token(sym_key)
    print('http server is starting on {} port {}...'.format(args.hostname, args.port))
    server_address = ('127.0.0.1', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy\n')
    print('Try with curl:')
    port = args.port
    if port == 80:
        port = ''
    else:
        port = ':' + str(port)
    print('curl --proto HTTP --head -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}'.
          format(eToken.serialize(), port))
    print('curl --proto HTTP -i -X GET -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}/get'.
          format(eToken.serialize(), port))
    print('curl --proto HTTP -i -X POST -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}/post'.
          format(eToken.serialize(), port))
    print('curl --proto HTTP -i -X DELETE -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}/delete'.
          format(eToken.serialize(), port))
    print('curl --proto HTTP -i -X PUT -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}/put'.
          format(eToken.serialize(), port))
    print('curl --proto HTTP -i -X PATCH -H "accept: application/json" -H "Authorization: Bearer {}" 127.0.0.1{}/patch'.
          format(eToken.serialize(), port))
    print()
    httpd.serve_forever()


if __name__ == '__main__':
    main()
