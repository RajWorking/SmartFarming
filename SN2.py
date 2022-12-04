import socket
import json
from fastecdsa import point, encoding
from sys import argv

from src.config import *
from src.roles.SN import *

f = open('keys2.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['TC'])
key = (obj['pr'], point.Point(obj['Pub']['x'], obj['Pub']['y']))

iot = SN(cred, key)
print(iot.pub_key, "\n")

s = socket.socket()
s.connect((argv[1], int(argv[2])))  # 10.42.0.1

sessionkey_path = 'key_SN1_SN2.pub'
iot.D2D_respond(s, sessionkey_path)
data = encryptMsg(sessionkey_path)
sendMsg(s, data)

s.close()
