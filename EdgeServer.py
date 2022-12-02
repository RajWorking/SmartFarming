import socket
import json
from sys import argv

from src.config import *
from src.roles.ES import *
from src.ElGamal import *

f = open('cred_ES.json', 'r')
obj = json.load(f)
f.close()

priv_key, pub_key = keys.import_key('ES.key')
es = ES((obj['RID'], obj['TID'], obj['gateways']), (priv_key, pub_key))
print(es.pub_key, "\n")

############################

s = socket.socket()
s.bind(('', int(argv[1])))
s.listen(1)
conn, _ = s.accept()

data = recvMsg(conn)
privkey_path = 'ES.key'
data = ElGamal.decrypt(data, privkey_path)

conn.close()

############################

# s = socket.socket()
# s.connect(('127.0.0.1', int(argv[2])))  # 10.42.0.1

# publickey_path = 'ES.pub'
# data = ElGamal.encrypt(publickey_path)
# sendMsg(s, data)

# s.close()
