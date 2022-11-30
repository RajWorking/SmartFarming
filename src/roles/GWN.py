import random
import hashlib
from datetime import datetime
from fastecdsa import keys, curve, point

from src.config import *
from src.utils import *


class GWN:
    """
    This class contains code for IoT Smart Device
    """

    def __init__(self, id):
        """
        id: (RID, TID)
        key: (priv_key, pub_key)
        sensors: [(RIDs, TIDs, TCs)]
        """
        ((self.RID, self.TID), self.sensors) = id

        self.priv_key = random.randint(1, q)
        self.pub_key = keys.get_public_key(self.priv_key, curve.P256)

    def D2D_respond(self, s):
        data = recvMsgSocket(s)
        print("Recieved Message: ")
        print(data)
        print()

        TS = int(datetime.now().timestamp())
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

        # r = random.randint(1, q)
        # TS = int(datetime.now().timestamp())

        # m = hashlib.sha256()
        # m.update(self.TID.to_bytes(qL, 'big'))
        # m.update(bytes.fromhex(self.RID))
        # m.update(bytes.fromhex(self.TC))
        # m.update(r.to_bytes(qL, 'big'))
        # m.update(self.priv_key.to_bytes(qL, 'big'))
        # m.update(TS.to_bytes(qL, 'big'))
        # y = int(m.hexdigest(), 16) % q

        # Y = keys.get_public_key(y, curve.P256)

        # SK = y * pointX

        # m = hashlib.sha256()
        # m.update(self.TID.to_bytes(qL, 'big'))
        # m.update(data["TID"].to_bytes(qL, 'big'))
        # m.update(self.pub_key.x.to_bytes(qL, 'big'))
        # m.update(self.pub_key.y.to_bytes(qL, 'big'))
        # m.update(SK.x.to_bytes(qL, 'big'))
        # m.update(SK.y.to_bytes(qL, 'big'))
        # m.update(TS.to_bytes(qL, 'big'))

        # Sig = (y + self.priv_key * int(m.hexdigest(), 16)) % q

        # print("Sending Message...")
        # input()

        # data = {'TID': self.TID,
        #         'Y': {
        #             'x': Y.x,
        #             'y': Y.y
        #         },
        #         'Sig': Sig,
        #         'Pub': {
        #             'x': self.pub_key.x,
        #             'y': self.pub_key.y
        #         },
        #         'TS': TS}
        # sendMsgSocket(s, data)

        # print("---------------------------------\n")
        # ############################

        # data = recvMsgSocket(s)
        # print("Recieved Message: ")
        # print(data)
        # print()

        # TS = int(datetime.now().timestamp())
        # if (abs(TS - data["TS"]) > dT):
        #     print("Took too long!! Try again.")
        #     return

        # m = hashlib.sha256()
        # m.update(SK.x.to_bytes(qL, 'big'))
        # m.update(SK.y.to_bytes(qL, 'big'))
        # m.update(data["TS"].to_bytes(qL, 'big'))

        # if (data["SKV"] != int(m.hexdigest(), 16)):
        #     print("Incorrect Session Key Verifier!! Try again.")
        #     return

        # print("Successfully established Session Key.")
