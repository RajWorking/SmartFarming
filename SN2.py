import socket
from _thread import *
import json
import random
import hashlib
from datetime import datetime
from fastecdsa import keys, curve, point

from sys import argv
from config import *
from roles import IOT_device as SN


def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf:
            return None
        buf += newbuf
        count -= len(newbuf)
    return buf


def sendMsg(s, msg):
    sz = len(json.dumps(msg).encode())  # length of object
    s.sendall(sz.to_bytes(4, byteorder='big'))
    s.sendall(json.dumps(msg).encode())


def recvMsg(s):
    data = recvall(s, 4)
    if not data:
        return
    len = int.from_bytes(data, 'big')
    data = json.loads(recvall(s, len).decode())
    return data


def D2D():
    s = socket.socket()
    s.connect(('127.0.0.1', int(argv[1])))  # 10.42.0.1

    ############################

    print("Recieved Message: ")
    data = recvMsg(s)
    print(data)
    print()

    TS2 = int(datetime.now().timestamp())
    if (abs(TS2 - data["TS"]) > dT):
        print("Took too long!! Try again.")
        return

    pointX = point.Point(data["X"]["x"], data["X"]["y"])
    pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

    m = hashlib.sha256()
    m.update(data["TID"].to_bytes(qL, 'big'))
    m.update(data["Pub"]["x"].to_bytes(qL, 'big'))
    m.update(data["Pub"]["y"].to_bytes(qL, 'big'))
    m.update(data["TS"].to_bytes(qL, 'big'))

    if (keys.get_public_key(data["Sig"], curve.P256) != (pointX + int(m.hexdigest(), 16) * pointPub)):
        print("Failed to verify Signature! Try again.")
        return

    print("Signature Verified.")

    print("---------------------------------\n")
    ############################

    TS2 = int(datetime.now().timestamp())
    r = random.randint(1, q)

    print("Sending Message...")
    data = {'sig': 1234,
            'msg': 5678,
            'pk': (34, 67)}
    sendMsg(s, data)
    print()

    s.close()


f = open('keys2.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key)


if __name__ == '__main__':
    D2D()
