import socket
import json
from sys import argv

from src.config import *
from src.roles.GWN import *

f = open('keysG.json', 'r')
obj = json.load(f)
f.close()

gwn = GWN((obj['RID'], obj['TID'], obj['sensors']))
print(gwn.pub_key, "\n")

############################

s = socket.socket()
s.bind(('', int(argv[1])))
s.listen(1)
conn, _ = s.accept()

sessionkey_path = 'key_SN1_GWN.pub'
gwn.D2D_respond(conn, sessionkey_path)
data = recvMsg(conn)
decryptMsg(data, sessionkey_path)

conn.close()
