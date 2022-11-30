from fastecdsa import keys, curve
import random
import hashlib
from datetime import datetime
from src.config import *


class RA:
    """
    This class contains code for
    RA (Registeration Authority) or KGC (Key Generation Center)
    """

    def __init__(self):
        self.mk = random.randint(1, q)  # master key

    def SN_KeyGen(self):
        ID = random.randint(1, q)
        TID = random.randint(1, q)
        s1 = random.randint(1, q)
        priv_key = random.randint(1, q)
        pub_key = keys.get_public_key(priv_key, curve.P256)

        m = hashlib.sha256()
        m.update(ID.to_bytes(qL, 'big'))
        m.update(s1.to_bytes(qL, 'big'))
        m.update(self.mk.to_bytes(qL, 'big'))
        RID = m.hexdigest()

        RTS = int(datetime.now().timestamp())
        m = hashlib.sha256()
        m.update(bytes.fromhex(RID))
        m.update(priv_key.to_bytes(qL, 'big'))
        m.update(self.mk.to_bytes(qL, 'big'))
        m.update(RTS.to_bytes(qL, 'big'))
        TC = m.hexdigest()

        return ((RID, TID, TC), (priv_key, pub_key))
    
    def GWN_KeyGen(self):
        ID = random.randint(1, q)
        TID = random.randint(1, q)
        g1 = random.randint(1, q)
        RTS = int(datetime.now().timestamp())

        m = hashlib.sha256()
        m.update(ID.to_bytes(qL, 'big'))
        m.update(g1.to_bytes(qL, 'big'))
        m.update(self.mk.to_bytes(qL, 'big'))
        m.update(RTS.to_bytes(qL, 'big'))
        RID = m.hexdigest()

        return ((RID, TID), [])
