import socket
import json
from sys import argv

from src.config import *
from src.roles.GWN import *

f = open('keysG.json', 'r')
obj = json.load(f)
f.close()

cred = (obj['RID'], obj['TID'], obj['sensors'])

gwn = GWN(cred)
print(gwn.pub_key, "\n")

############################

s = socket.socket()
s.bind(('', int(argv[1])))
s.listen(1)
conn, _ = s.accept()

gwn.D2D_respond(s)

conn.close()
