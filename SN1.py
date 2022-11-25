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


def sendMsg(conn, msg):
    data = json.dumps(msg).encode()
    sz = len(data)
    conn.send(sz.to_bytes(4, byteorder='big'))
    conn.send(data)


def recvMsg(conn):
    data = recvall(conn, 4)
    if not data:
        return
    len = int.from_bytes(data, 'big')
    data = json.loads(recvall(conn, len).decode())
    return data


def D2D():
    s = socket.socket()
    s.bind(('', int(argv[1])))
    s.listen(1)
    conn, _ = s.accept()

    ############################

    r = random.randint(1, q)
    TS = int(datetime.now().timestamp())

    m = hashlib.sha256()
    m.update(bytes.fromhex(iot.RID))
    m.update(iot.TID.to_bytes(qL, 'big'))
    m.update(bytes.fromhex(iot.TC))
    m.update(iot.priv_key.to_bytes(qL, 'big'))
    m.update(TS.to_bytes(qL, 'big'))
    m.update(r.to_bytes(qL, 'big'))
    x = int(m.hexdigest(), 16) % q

    X = keys.get_public_key(x, curve.P256)

    m = hashlib.sha256()
    m.update(iot.TID.to_bytes(qL, 'big'))
    m.update(iot.pub_key.x.to_bytes(qL, 'big'))
    m.update(iot.pub_key.y.to_bytes(qL, 'big'))
    m.update(TS.to_bytes(qL, 'big'))

    Sig = (x + iot.priv_key * int(m.hexdigest(), 16)) % q

    print("Sending Message...")
    input()

    data = {'TID': iot.TID,
            'X': {
                'x': X.x,
                'y': X.y
            },
            'Sig': Sig,
            'Pub': {
                'x': iot.pub_key.x,
                'y': iot.pub_key.y
            },
            'TS': TS}
    sendMsg(conn, data)

    print("---------------------------------\n")
    ############################

    data = recvMsg(conn)
    print("Recieved Message: ")
    print(data)
    print()

    TS = int(datetime.now().timestamp())
    if (abs(TS - data["TS"]) > dT):
        print("Took too long!! Try again.")
        return

    pointY = point.Point(data["Y"]["x"], data["Y"]["y"])
    pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

    SK = x * pointY

    m = hashlib.sha256()
    m.update(data["TID"].to_bytes(qL, 'big'))
    m.update(iot.TID.to_bytes(qL, 'big'))
    m.update(data["Pub"]["x"].to_bytes(qL, 'big'))
    m.update(data["Pub"]["y"].to_bytes(qL, 'big'))
    m.update(SK.x.to_bytes(qL, 'big'))
    m.update(SK.y.to_bytes(qL, 'big'))
    m.update(data["TS"].to_bytes(qL, 'big'))

    if (keys.get_public_key(data["Sig"], curve.P256) != (pointY + int(m.hexdigest(), 16) * pointPub)):
        print("Failed to verify Signature! Try again.")
        return

    print("Signature Verified.")

    print("---------------------------------\n")
    ############################

    TS = int(datetime.now().timestamp())
    m = hashlib.sha256()
    m.update(SK.x.to_bytes(qL, 'big'))
    m.update(SK.y.to_bytes(qL, 'big'))
    m.update(TS.to_bytes(qL, 'big'))

    SKV = int(m.hexdigest(), 16)

    print("Sending Message...")
    input()

    data = {
        'SKV': SKV,
        'TS': TS,
    }
    sendMsg(conn, data)
    
    print("Successfully established Session Key.")
    
    ############################
    conn.close()


f = open('keys1.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key, "\n")

if __name__ == '__main__':
    D2D()
