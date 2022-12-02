from src.roles import RA, GWN, ES
from src.config import *
import json
from fastecdsa import keys, curve, point

ra = RA.RA()

iot_devices = []
#############

# number of IOT devices
N = 2

for i in range(1, N+1):
    cred = ra.SN_KeyGen()
    ((RID, TID, TC), (priv_key, pub_key)) = cred

    cred_json = {
        "RID": RID,
        "TID": TID,
        "TC": TC,
        "pr": priv_key,
        "Pub": {
            "x": pub_key.x,
            "y": pub_key.y,
        }
    }
    print(json.dumps(cred_json, indent=2))

    iot_devices.append({
        "RID": RID,
        "TID": TID,
        "TC": TC, }
    )

    with open('keys%d.json' % i, 'w') as f:
        f.write(json.dumps(cred_json))

print("---------------------------------\n")
############################

cred = ra.Server_KeyGen()
((RIDg, TIDg), _) = cred

priv_key, pub_key = keys.gen_keypair(curve.P256)
gwn = GWN.GWN((RIDg, TIDg, iot_devices), (priv_key, pub_key))

cred_json = {
    "RID": RIDg,
    "TID": TIDg,
    "sensors": iot_devices
}
print(json.dumps(cred_json, indent=2))

with open('cred_G.json', 'w') as f:
    f.write(json.dumps(cred_json))
    
keys.export_key(gwn.priv_key, curve=curve.P256, filepath='GWN.key')
keys.export_key(gwn.pub_key, curve=curve.P256, filepath='GWN.pub')

print("---------------------------------\n")
############################

cred = ra.Server_KeyGen()
((RIDe, TIDe), _) = cred

priv_key, pub_key = keys.gen_keypair(curve.P256)
es = ES.ES((RIDe, TIDe, [RIDg]), (priv_key, pub_key))

cred_json = {
    "RID": RIDe,
    "TID": TIDe,
    "gateways": [RIDg]
}
print(json.dumps(cred_json, indent=2))

with open('cred_ES.json', 'w') as f:
    f.write(json.dumps(cred_json))

keys.export_key(es.priv_key, curve=curve.P256, filepath='ES.key')
keys.export_key(es.pub_key, curve=curve.P256, filepath='ES.pub')
