import socket
import json
from sys import argv

from src.config import *
from src.roles.GWN import *
from src.ElGamal import *

f = open('cred_G.json', 'r')
obj = json.load(f)
f.close()

priv_key, pub_key = keys.import_key('GWN.key')
gwn = GWN((obj['RID'], obj['TID'], obj['sensors']), (priv_key, pub_key))
print(gwn.pub_key, "\n")

############################

s = socket.socket()
s.bind((argv[1], int(argv[2])))

# while True:
s.listen(1)
conn, _ = s.accept()

sessionkey_path = 'key_SN1_GWN.pub'
gwn.D2G_respond(conn, sessionkey_path)
data = recvMsg(conn)
print('GatewayNode: Received Data from Sensor Node')
decryptMsg(data, sessionkey_path)

conn.close()

############################

s = socket.socket()
s.connect((argv[3], int(argv[4])))   # 10.42.0.1

publickey_path = 'ES.pub'
data = ElGamal.encrypt(publickey_path)

# print(json.dumps(data, indent=2))
print('Received data from Sensor Node')

print('GatewayNode: Sending Data to Edge Server')
sendMsg(s, data)
print('GatewayNode: Data sent')

s.close()
