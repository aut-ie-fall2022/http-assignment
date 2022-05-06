from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse, sys
import requests
from socketserver import ThreadingMixIn
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, DecodeError
from urllib3.exceptions import InsecureRequestWarning
import urllib3
urllib3.disable_warnings(InsecureRequestWarning)

hostname = 'httpbin.org'
port = 8080

signature = 'My_Big_Fat_Secret'
# test_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTmVnYXIiLCJpYXQiOjE2NDk1MjY5ODUsImV4cCI6MTY3OTUyNjk4NX0.1n9Gqa5kKmqNBAHei0vDQHYWE48p7GDblSQcedWxt3c'

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def do_GET(self, body=True):
        print('************newRequest************')
        sent_req = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            request_header = self.parse_headers()

            verify = self.authentication(request_header)
            if not verify:
                self.send_error(code=403, message=' You Can''t access the Server! Authentication Failed')
                return


            response = requests.get(url, headers=merge_two_dicts(request_header, set_header()), verify=False)
            sent_req = True

            self.send_response(response.status_code)
            self.send_response_headers(response)
            message = response.text

            if body:
                self.wfile.write(message.encode(encoding='UTF-8', errors='strict'))

            return

        finally:
            if not sent_req:
                self.send_error(404, 'Not Found')

    def authentication(self, headers):
        verify = False

        if 'Authorization' not in headers.keys():
            return verify

        auth_header = headers['Authorization'].split(' ')

        if auth_header[0] == 'Bearer':
            # checking expire time
            # verifying signature
            token = auth_header[1]
            try:
                header_data = jwt.get_unverified_header(token)

                payload = jwt.decode(token, key=signature, algorithms=[header_data['alg'], ])

                if payload['name'] == 'Negar':
                    verify = True
                else:
                    self.send_error(code=403, message='you don''t have Authorization to Access this Server')

                return verify

            except (ExpiredSignatureError, InvalidSignatureError, DecodeError) as error:
                print(f'Unable to decode the token , error: {error}')
                return verify

        else:
            print('Error : {} Authorization'.format(headers['Authorization']))
            return verify

    def parse_headers(self):
        request_headers = {}

        header_lines = [h.strip() for h in str(self.headers).split('\n')]
        for line in header_lines:
            line_parts = line.split(':')

            if len(line_parts) == 2:
                request_headers[line_parts[0].strip()] = line_parts[1].strip()

        return request_headers

    def send_response_headers(self, resp):
        response_headers = resp.headers

        for key in response_headers:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:

                self.send_header(key, response_headers[key])

        self.send_header('Content-Length', len(resp.content))
        self.end_headers()


def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=port,
                        help='serve HTTP requests on specified port (default: ' + str(port) + ')')
    parser.add_argument('--hostname', dest='hostname', type=str, default=hostname,
                        help='hostname to be processed (default: ' + hostname + ')')
    args = parser.parse_args(argv)
    return args


def merge_two_dicts(x, y):
    return {**x,**y}


def set_header():
    return {'Host': hostname}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


def main(argv=sys.argv[1:]):
    global hostname, port
    args = parse_args(argv)
    hostname = args.hostname
    port = args.port

    print('http server is starting on {} port {}...'.format(hostname, port))
    server_address = ('127.0.0.1', 80)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running as reverse proxy')
    httpd.serve_forever()


if __name__ == '__main__':
    main()
