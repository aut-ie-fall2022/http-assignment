from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import jwt



def mergeDicts(a, b):
    return a | b

hostname = 'httpbin.org'


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    httpVersion = 'HTTP/1.0'
    def do_GET(self, body=True):
        sent = False
        try:
            url = 'https://{}{}'.format(hostname, self.path)
            req_header = self.parse_headers()

            print(url)
            headers = {'Host': hostname}
            # send get request
            resp = requests.get(url, headers=mergeDicts(req_header, headers), verify=False)
            sent = True

            self.send_response(resp.status_code)
            self.send_resp_headers(resp)
            msg = resp.text
            if body:
                self.wfile.write(msg.encode(encoding='UTF-8', errors='strict'))
            return
        finally:
            if not sent:
                self.send_error(404, 'error trying to proxy')


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

    def parse_headers(self):
        req_header = {}
        s = str(self.headers)

        for line in s.split("\n"):
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]

        print(req_header)

        try:
            token = req_header['Athurization']
            newToken = token.split(" ")[1]
            print(newToken)
            de = jwt.decode(newToken, key="hi", algorithms=['HS256'])

            print("encode "+str(de))
        except:
            print("Error in jwt Authentication")
            self.send_error(404, 'error trying to proxy')
            raise Exception("Error in jwt Authentication")

        return req_header



def main():
    global hostname
    hostname = "httpbin.org"
    print('server is starting on {} port {}...'.format(hostname, 80))
    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print(' server is running as reverse proxy on {} port {}'.format('127.0.0.1', 8081))
    httpd.serve_forever()


if __name__ == '__main__':
    main()