import random
import hashlib
from datetime import datetime
from fastecdsa import keys, curve, point

from src.config import *
from src.utils import *


class GWN:
    """
    This class contains code for Gateway Node
    """

    def __init__(self, id, keypair):
        """
        id: (RID, TID)
        keypair: (priv_key, pub_key)
        sensors: [(RIDs, TIDs, TCs)]
        """
        self.RID, self.TID, self.sensors = id
        self.priv_key, self.pub_key = keypair

    def D2G_respond(self, conn, sessionkey_path):
        data = recvMsg(conn)
        print("Recieved Message: ")
        print(json.dumps(data, indent=2))
        print()

        TS = int(datetime.now().timestamp())
        print("diff", abs(TS - data["TS"]))
        print("dt", dT)
        if (abs(TS - data["TS"]) > dT):
            print("Took too long!! Try again.")
            return

        pointA = point.Point(data["A"]["x"], data["A"]["y"])
        pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

        m = hashlib.sha256()
        m.update(data["x"].to_bytes(qL, 'big'))
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(pointA.x.to_bytes(qL, 'big'))
        m.update(pointA.y.to_bytes(qL, 'big'))
        m.update(data["TS"].to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["TC"]))

        if (keys.get_public_key(data["Sig"], curve.P256) != (pointA + int(m.hexdigest(), 16) * pointPub)):
            print("Failed to verify Signature! Try again.")
            return

        print("Signature Verified.")

        print("---------------------------------\n")
        # ############################

        m = hashlib.sha256()
        m.update(bytes.fromhex(data["TC"]))
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["RID"]))
        m.update(data["TS"].to_bytes(qL, 'big'))

        y_s = data["x"] ^ int(m.hexdigest(), 16)

        q_g = random.randint(1, q)
        TS = int(datetime.now().timestamp())

        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(q_g.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["RID"]))
        m.update(TS.to_bytes(qL, 'big'))
        b = int(m.hexdigest(), 16) % q

        B = keys.get_public_key(b, curve.P256)
        DK = b * pointA

        m = hashlib.sha256()
        m.update(self.priv_key.to_bytes(qL, 'big'))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.RID))
        m.update(bytes.fromhex(data["TC"]))
        m.update(TS.to_bytes(qL, 'big'))
        z = int(m.hexdigest(), 16)
        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["TC"]))
        m.update(data["TS"].to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["RID"]))

        y_g = z ^ int(m.hexdigest(), 16)

        m = hashlib.sha256()
        m.update(DK.x.to_bytes(qL, 'big'))
        m.update(DK.y.to_bytes(qL, 'big'))
        m.update(y_s.to_bytes(qL, 'big'))
        m.update(z.to_bytes(qL, 'big'))

        SK = int(m.hexdigest(), 16) % q

        TID_new = random.randint(1, q)

        m = hashlib.sha256()
        m.update(SK.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        TID_s = TID_new ^ int(m.hexdigest(), 16)

        m = hashlib.sha256()
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(data["TC"]))
        m.update(y_g.to_bytes(qL, 'big'))
        m.update(self.pub_key.x.to_bytes(qL, 'big'))
        m.update(self.pub_key.y.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        Sig = (b + self.priv_key * int(m.hexdigest(), 16)) % q

        print("Sending Message...")
        # input()

        data = {'Pub': {
            'x': self.pub_key.x,
            'y': self.pub_key.y
        },
            'TID': self.TID,
            'B': {
            'x': B.x,
            'y': B.y
        },
            'y': y_g,
            'Sig': Sig,
            'TID_s': TID_s,
            'TS': TS}

        sendMsg(conn, data)

        print("---------------------------------\n")
        ############################

        data = recvMsg(conn)
        print("Recieved Message: ")
        print(json.dumps(data, indent=2))
        print()

        TS = int(datetime.now().timestamp())
        if (abs(TS - data["TS"]) > dT):
            print("Took too long!! Try again.")
            return

        m = hashlib.sha256()
        m.update(SK.to_bytes(qL, 'big'))
        m.update(TID_new.to_bytes(qL, 'big'))
        m.update(data["TS"].to_bytes(qL, 'big'))

        if (data["SKV"] != int(m.hexdigest(), 16)):
            print("Incorrect Session Key Verifier!! Try again.")
            return

        keys.export_key(SK, curve=curve.P256, filepath=sessionkey_path)
        print("Successfully established Session Key.")
