import socket
import json
from fastecdsa import point
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
s.connect(('127.0.0.1', int(argv[1])))  # 10.42.0.1

iot.D2D_respond(s)

s.close()
