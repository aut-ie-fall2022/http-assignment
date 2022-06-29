from flask import Flask, request, redirect, Response, make_response
import requests
import jwt
import calendar
import datetime

"""
JWT Token :
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImxpbGhlZGkiLCJpYXQiOjE3MTYyMzkwMjJ9.mdyyaj-1L0h4cF5ZOQww9vzAjgm6L2e_Rh6jIcbKXy8
Header :
{
  "alg": "HS256",
  "typ": "JWT"
}
Payload :
{
  "sub": "1234567890",
  "name": "lilhedi",
  "iat": 1716239022
}
VERIFY SIGNATURE :
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  
your-256-bit-secret

)
"""

app = Flask(__name__)
# SITE_NAME = 'http://localhost:8081'
SITE_NAME = 'https://httpbin.org/'

# @app.route('/<path:path>', methods=['GET', 'POST', 'DELETE'])
@app.route('/', methods=['GET', 'POST', 'DELETE'])
def proxy():
    global SITE_NAME
    if authorization_service():
        if request.method == 'GET':
            resp = requests.get(f'{SITE_NAME}')  # reverse proxy sends a GET request to {SITE_NAME}{path}
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(name, value) for (name, value) in resp.raw.headers.items() if
                       name.lower() not in excluded_headers]
            response = Response(resp.content, resp.status_code, headers)  # returning the response to the client
            return response
        elif request.method == 'POST':
            resp = requests.post(f'{SITE_NAME}',
                                 json=request.get_json())  # reverse proxy sends a POST request to {SITE_NAME}{path} along with the data
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(name, value) for (name, value) in resp.raw.headers.items() if
                       name.lower() not in excluded_headers]
            response = Response(resp.content, resp.status_code, headers)
            return response
        elif request.method == 'DELETE':
            resp = requests.delete(f'{SITE_NAME}').content
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(name, value) for (name, value) in resp.raw.headers.items() if
                       name.lower() not in excluded_headers]
            response = Response(resp.content, resp.status_code, headers)
            return response
    else:
        return make_response('Authentication error', 401)


def authorization_service():

    token = str(request.headers.get('Authorization'))
    token = token.split(" ")[1]
    # print(token)
    if token:
        try:
            data = jwt.decode(token, "your-256-bit-secret", algorithms=["HS256"])
            date = datetime.datetime.utcnow()
            utc_time = calendar.timegm(date.utctimetuple())
            if int(data.get('iat')) > utc_time:
                print("JWT is valid")
                return True
            else:
                print("JWT is not valid anymore")
        except:
            print("Couldn't decode JWT")
    else:
        print("HTTP request doesn't have any Authentication header")
    return False


if __name__ == '__main__':
    app.run(debug=True, port=80)
