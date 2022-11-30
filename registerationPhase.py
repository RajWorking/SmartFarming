from src.roles import RA
from src.config import *
import numpy as np
import json

ra = RA.RA()

iot_devices = []
#############

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
    print(cred_json)

    iot_devices.append({
        "RID": RID,
        "TID": TID,
        "TC": TC, }
    )

    with open('keys%d.json' % i, 'w') as f:
        f.write(json.dumps(cred_json))

#############

cred = ra.GWN_KeyGen()
((RID, TID), _) = cred

cred_json = {
    "RID": RID,
    "TID": TID,
    "sensors": iot_devices
}
print(cred_json)

with open('keysG.json', 'w') as f:
    f.write(json.dumps(cred_json))
