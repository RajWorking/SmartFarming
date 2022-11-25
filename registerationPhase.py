from roles import RA
from config import *
import numpy as np
import json

ra = RA.RA()

for i in range(1, N+1):
    cred = ra.KeyGen()
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

    with open('keys%d.json' % i, 'w') as f:
        f.write(json.dumps(cred_json))
