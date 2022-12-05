import socket
import json
from sys import argv

from src.config import *
from src.roles.ES import *
from src.ElGamal import *
import base64
import base64

f = open('cred_ES.json', 'r')
obj = json.load(f)
f.close()

priv_key, pub_key = keys.import_key('ES.key')
es = ES((obj['RID'], obj['TID'], obj['gateways']), (priv_key, pub_key))
print(es.pub_key, "\n")

############################

s = socket.socket()
s.bind((argv[1], int(argv[2])))

# while True:
s.listen(1)
conn, _ = s.accept()

data = recvMsg(conn)
print('Data received from Gateway node')
privkey_path = 'ES.key'
data = ElGamal.decrypt(data, privkey_path)

conn.close()

############################

s = socket.socket()
s.connect((argv[3], int(argv[4])))  # 10.42.0.1

# publickey_path = 'ES.pub'
# data = ElGamal.encrypt(publickey_path)
print('Sending data to cloud server')
sendMsg(s, base64.b64encode(data).decode('utf-8'))
print('Data sent')

s.close()
