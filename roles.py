

import numpy as np
from fastecdsa import keys, curve, point
import random
import hashlib
from datetime import datetime
from config import *


class RA:
    """
    This class contains code for
    RA (Registeration Authority) or KGC (Key Generation Center)
    """

    def __init__(self):
        self.mk = random.randint(1, q)  # master key

    def KeyGen(self):
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


class IOT_device:
    """
    This class contains code for IoT Smart Device
    """

    def __init__(self, id, key):
        """
        id: (RID, TID, TC)
        key: (priv_key, pub_key)
        """
        RID, TID, TC = id
        priv_key, pub_key = key

        self.RID = RID
        self.TID = TID
        self.TC = TC
        self.priv_key = priv_key
        self.pub_key = pub_key
