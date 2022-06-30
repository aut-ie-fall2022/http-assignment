from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, os, random, sys, requests
import time
from socketserver import ThreadingMixIn
#import threading

from datetime import datetime, timedelta
import jwt

valid_users = ["arman", "omid", "asad"]
def merge_two_dicts(x, y):
    return x | y

def set_header():
    headers = {
        'Host': hostname
    }

    return headers

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def do_HEAD(self):
        self.do_GET(body=False)
        return
        
    def do_GET(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            req_header = self.parse_headers()
            to_str = str(self.headers)
            for line in to_str.split("\n"):
                auth = line[len("Authorization: Bearer ") : ]
                break

            print(auth)
            SECRET_KEY = "hatami"
            token = auth
            ALGORITHM = "HS256"
            ACCESS_TOKEN_EXPIRE_MINUTES = 30
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            except:
                print("invalid authentication")
                return
            print(payload, flush=True)
            valid = True
            current_time = time.time()
            if payload["iat"] + ACCESS_TOKEN_EXPIRE_MINUTES * 60 < current_time:
                valid = False
            if payload["name"] not in valid_users:
                valid = False
            if valid:
                print(url)
                resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
                sent = True
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)
                msg = resp.text
                if body:
                    self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
                return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print ('responce')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                print (key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=8081,
                        help='serve HTTP requests on specified port (default: random)')
    parser.add_argument('--hostname', dest='hostname', type=str, default='httpbin.org',
                        help='hostname to be processd (default: httpbin.org)')
    args = parser.parse_args(argv)
    return args

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(argv=sys.argv[1:]):
    global hostname
    args = parse_args(argv)
    hostname = args.hostname
    server_address = ('127.0.0.1', args.port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()

if __name__ == '__main__':
    main()