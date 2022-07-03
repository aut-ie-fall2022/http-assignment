from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import time
import threading
import jwt
import requests

PORT = 7412
HOST = "localhost"
# main server
target = 'httpbin.org/'


def set_header():
    headers = {
        'Host': HOST
    }

    return headers


def merge_two_dicts(x, y):
    return x | y


class MyHTTP(BaseHTTPRequestHandler):

    def do_GET(self, body=True):
        sent = False
        try:
            # url of the main server
            url = 'https://{}{}'.format(target, self.path)
            req_header = self.parse_headers()

            # get the token out from jwt
            token = self.get_jwt_token()

            # get the header of jwt
            header_data = jwt.get_unverified_header(token)

            from jwt.exceptions import ExpiredSignatureError
            try:
                payload = jwt.decode(token, key='my-secret-key', algorithms=[header_data['alg'], ])
                print(payload)

            except ExpiredSignatureError as error:
                self.send_error(401, 'error trying to proxy')
                print(f'Unable to decode the token, error: {error}')

            # if authorizing is successful then reverse proxy sends the request to the main server
            # and it will get the response.
            resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
            sent = True

            self.send_response(200)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8', errors='strict'))
                print("doneeeeeeeeeeee")
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')

    # do_post isn't complete yet
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        message = threading.currentThread().getName()
        date = time.strftime("%Y-%M-%D %H:%M:%S", time.localtime(time.time()))
        self.wfile.write(bytes("time : " + date, "utf-8"))

    def get_jwt_token(self):
        values = self.headers.values()
        s = values[0].split()
        token = s[1]
        return token

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 2)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        print('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding',
                           'content-length', 'Content-Length']:
                print(key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()


# for multi threading and serve multiple clients at a time
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


if __name__ == '__main__':
    server = ThreadedHTTPServer((HOST, PORT), MyHTTP)

    print(f"Server now running on port {PORT}")
    server.serve_forever()
    server.server_close()
