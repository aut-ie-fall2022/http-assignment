"""
-- Reverse Proxy server with python --
ToDo :
    create jwt token --> Done
    create http request with jwt in postman --> Done
    get http packet in python --> Done
    authenticate jwt --> Done
    if ok then sent http to server and return result --> Done

JWT Token :
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hbWlpaSIsImlhdCI6MTkxNjIzOTAyMn0.SWiw6XinBqYTGvdi8OWUUOzaG12JpViSCxQTGitnPvE
Header :
{
  "typ": "JWT",
  "alg": "HS256"
}

Payload :
{
  "sub": "1234567890",
  "name": "namiii",
  "iat": 1916239022
}

VERIFY SIGNATURE :
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  strongPWDHaHa
)
"""

import socket
from threading import Thread
import jwt
import calendar
import datetime


class ClientThread(Thread):

    def __init__(self, ip, port):
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        print("[+] New thread started for " + ip + ":" + str(port))

    def run(self):
        condition = 0
        while True:
            data = conn.recv(2048)
            if len(data) == 0:
                break
            data_string = data.decode("utf-8").split("\n")
            flag = 0
            token = ""
            for i in range(0, len(data_string)):
                if data_string[i].startswith("Authorization"):
                    token = data_string[i]
                    flag = 1
                    break
            if flag == 0:
                print("HTTP request doesn't have Authentication header")
                break
            else:
                token = token[22:-1]
                try:
                    user_data = jwt.decode(token, "strongPWDHaHa", algorithms=["HS256"])
                    condition = 1
                    time = int(user_data.get("iat"))
                    date = datetime.datetime.utcnow()
                    utc_time = calendar.timegm(date.utctimetuple())
                    if int(utc_time) < time:
                        print("Authentication : Successful")
                        print("Data :", end=" ")
                        print(user_data)
                        print("send request to server")
                        condition = 2
                        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        clientSocket.connect(("127.0.0.1", 8080))
                        clientSocket.send(data)
                        dataFromServer = clientSocket.recv(10000)
                        print("get data from server")
                        condition = 3
                        conn.send(dataFromServer)
                        condition = 4
                        print("forward data to client")
                    else:
                        print("JWT is not valid anymore")
                        break
                except:
                    if condition == 0:
                        print("Authentication Failed")
                    elif condition == 1:
                        print("server is not available")
                    elif condition == 2:
                        print("cannot get data from server")
                    elif condition == 3:
                        print("cannot send data to client")
                    break
                finally:
                    print("*********************************")


TCP_IP = '0.0.0.0'
TCP_PORT = 80
BUFFER_SIZE = 2048
tcpSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpSock.bind((TCP_IP, TCP_PORT))
threads = []
print("Proxy server started ...")
print("*********************************")
while True:
    tcpSock.listen(4)
    (conn, (ip, port)) = tcpSock.accept()
    newThread = ClientThread(ip, port)
    newThread.start()
    threads.append(newThread)
