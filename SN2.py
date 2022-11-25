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

    data = recvMsg(s)
    print("Recieved Message: ")
    print(data)
    print()

    TS = int(datetime.now().timestamp())
    if (abs(TS - data["TS"]) > dT):
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

    r = random.randint(1, q)
    TS = int(datetime.now().timestamp())

    m = hashlib.sha256()
    m.update(iot.TID.to_bytes(qL, 'big'))
    m.update(bytes.fromhex(iot.RID))
    m.update(bytes.fromhex(iot.TC))
    m.update(r.to_bytes(qL, 'big'))
    m.update(iot.priv_key.to_bytes(qL, 'big'))
    m.update(TS.to_bytes(qL, 'big'))
    y = int(m.hexdigest(), 16) % q

    Y = keys.get_public_key(y, curve.P256)

    SK = y * pointX

    m = hashlib.sha256()
    m.update(iot.TID.to_bytes(qL, 'big'))
    m.update(data["TID"].to_bytes(qL, 'big'))
    m.update(iot.pub_key.x.to_bytes(qL, 'big'))
    m.update(iot.pub_key.y.to_bytes(qL, 'big'))
    m.update(SK.x.to_bytes(qL, 'big'))
    m.update(SK.y.to_bytes(qL, 'big'))
    m.update(TS.to_bytes(qL, 'big'))

    Sig = (y + iot.priv_key * int(m.hexdigest(), 16)) % q

    print("Sending Message...")
    # input()

    data = {'TID': iot.TID,
            'Y': {
                'x': Y.x,
                'y': Y.y
            },
            'Sig': Sig,
            'Pub': {
                'x': iot.pub_key.x,
                'y': iot.pub_key.y
            },
            'TS': TS}
    sendMsg(s, data)

    print("---------------------------------\n")
    ############################

    data = recvMsg(s)
    print("Recieved Message: ")
    print(data)
    print()
    
    TS = int(datetime.now().timestamp())
    if (abs(TS - data["TS"]) > dT):
        print("Took too long!! Try again.")
        return
    
    m = hashlib.sha256()
    m.update(SK.x.to_bytes(qL, 'big'))
    m.update(SK.y.to_bytes(qL, 'big'))
    m.update(data["TS"].to_bytes(qL, 'big'))

    if(data["SKV"] != int(m.hexdigest(), 16)):
        print("Incorrect Session Key Verifier!! Try again.")
        return
    
    print("Successfully established Session Key.")
    
    ############################
    s.close()


f = open('keys2.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key, "\n")


if __name__ == '__main__':
    D2D()
