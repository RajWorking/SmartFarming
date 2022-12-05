import socket
import json
from fastecdsa import point
from sys import argv

from src.config import *
from src.roles.SN import *

f = open('keys1.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key, "\n")

############################

s = socket.socket()
s.bind((argv[1], int(argv[2])))

# while True:
s.listen(1)

conn, _ = s.accept()
sessionkey_path = 'key_SN1_SN2.pub'
iot.D2D_initiate(conn, sessionkey_path)
data = recvMsg(conn)
decryptMsg(data, sessionkey_path)

conn.close()

############################

s = socket.socket()
s.connect((argv[3], int(argv[4])))  # 10.42.0.1

sessionkey_path = 'key_SN1_GWN.pub'
iot.D2G_initiate(s, sessionkey_path)
data = encryptMsg(sessionkey_path)
print('Sending Data to Gateway node')
sendMsg(s, data)
print('Data sent')
s.close()
