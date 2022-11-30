import socket
import json
from fastecdsa import point
from sys import argv

from src.config import *
from src.roles.SN import *

f = open('keys.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key, "\n")

############################

s = socket.socket()
s.bind(('', int(argv[1])))
s.listen(1)

conn, _ = s.accept()
sessionkey_path = 'key_SN1_SN2.pub'
iot.D2D_initiate(conn, sessionkey_path)
data = recvMsg(conn)
decryptMsg(data, sessionkey_path)

conn.close()

############################

s = socket.socket()
s.connect(('127.0.0.1', int(argv[2])))  # 10.42.0.1

sessionkey_path = 'key_SN1_GWN.pub'
iot.D2G_initiate(s, sessionkey_path)
data = encryptMsg(sessionkey_path)
sendMsg(s, data)

s.close()
