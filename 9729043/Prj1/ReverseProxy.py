from flask import Flask, request, redirect, Response, make_response
import requests
import jwt
import calendar
import datetime

ReverseProxy = Flask(__name__)


@ReverseProxy.route('/')
def revprox():
    try:
        jwt_token = str(request.headers.get('Authorization'))
        jwt_token = jwt_token.split(" ")[1]
        if jwt_token:
            try:
                decoded_token = jwt.decode(jwt_token, "IE_Practical_HW1", algorithms=["HS256"])
                time = datetime.datetime.utcnow()
                utc_time = calendar.timegm(time.utctimetuple())
                if int(decoded_token.get('exp')) > utc_time:

                    print("Valid Token!!")
                    # getting the response from httpbin
                    response = requests.get('https://httpbin.org')
                    # send the response to the client
                    final_response = Response(response.content, response.status_code, response.raw.headers.items())
                    return final_response
                else:
                    return make_response('Invalid Token!!', 401)
            except:
                return make_response('Cant decode the JWT Token', 401)
        else:
            return make_response('No Authentication header in the HTTP request', 401)
    except:
        return make_response('No Authentication header in the HTTP request', 401)


if __name__ == '__main__':
    ReverseProxy.run(debug=True, port=80)
