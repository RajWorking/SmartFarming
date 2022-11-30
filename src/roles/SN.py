import random
import hashlib
from datetime import datetime
from fastecdsa import keys, curve, point

from src.config import *
from src.utils import *


class SN:
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

    def D2D_initiate(self, conn):
        r = random.randint(1, q)
        TS = int(datetime.now().timestamp())

        m = hashlib.sha256()
        m.update(bytes.fromhex(self.RID))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.TC))
        m.update(self.priv_key.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))
        m.update(r.to_bytes(qL, 'big'))
        x = int(m.hexdigest(), 16) % q

        X = keys.get_public_key(x, curve.P256)

        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(self.pub_key.x.to_bytes(qL, 'big'))
        m.update(self.pub_key.y.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        Sig = (x + self.priv_key * int(m.hexdigest(), 16)) % q

        print("Sending Message...")
        input()

        data = {'TID': self.TID,
                'X': {
                    'x': X.x,
                    'y': X.y
                },
                'Sig': Sig,
                'Pub': {
                    'x': self.pub_key.x,
                    'y': self.pub_key.y
                },
                'TS': TS}
        sendMsgConn(conn, data)

        print("---------------------------------\n")
        ############################

        data = recvMsgConn(conn)
        print("Recieved Message: ")
        print(data)
        print()

        TS = int(datetime.now().timestamp())
        if (abs(TS - data["TS"]) > dT):
            print("Took too long!! Try again.")
            return

        pointY = point.Point(data["Y"]["x"], data["Y"]["y"])
        pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

        SK = x * pointY

        m = hashlib.sha256()
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(data["Pub"]["x"].to_bytes(qL, 'big'))
        m.update(data["Pub"]["y"].to_bytes(qL, 'big'))
        m.update(SK.x.to_bytes(qL, 'big'))
        m.update(SK.y.to_bytes(qL, 'big'))
        m.update(data["TS"].to_bytes(qL, 'big'))

        if (keys.get_public_key(data["Sig"], curve.P256) != (pointY + int(m.hexdigest(), 16) * pointPub)):
            print("Failed to verify Signature! Try again.")
            return

        print("Signature Verified.")

        print("---------------------------------\n")
        ############################

        TS = int(datetime.now().timestamp())
        m = hashlib.sha256()
        m.update(SK.x.to_bytes(qL, 'big'))
        m.update(SK.y.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        SKV = int(m.hexdigest(), 16)

        print("Sending Message...")
        # input()

        data = {
            'SKV': SKV,
            'TS': TS,
        }
        sendMsgConn(conn, data)

        keys.export_key(SK, curve=curve.P256, filepath='key_SN1_SN2.pub')
        print("Successfully established Session Key.")

    def D2D_respond(self, s):
        data = recvMsgSocket(s)
        print("Recieved Message: ")
        print(data)
        print()

        TS = int(datetime.now().timestamp())
        if (abs(TS - data["TS"]) > dT):
            print("Took too long!! Try again.")
            return

        pointX = point.Point(data["X"]["x"], data["X"]["y"])
        pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

        m = hashlib.sha256()
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(data["Pub"]["x"].to_bytes(qL, 'big'))
        m.update(data["Pub"]["y"].to_bytes(qL, 'big'))
        m.update(data["TS"].to_bytes(qL, 'big'))

        if (keys.get_public_key(data["Sig"], curve.P256) != (pointX + int(m.hexdigest(), 16) * pointPub)):
            print("Failed to verify Signature! Try again.")
            return

        print("Signature Verified.")

        print("---------------------------------\n")
        ############################

        r = random.randint(1, q)
        TS = int(datetime.now().timestamp())

        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.RID))
        m.update(bytes.fromhex(self.TC))
        m.update(r.to_bytes(qL, 'big'))
        m.update(self.priv_key.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))
        y = int(m.hexdigest(), 16) % q

        Y = keys.get_public_key(y, curve.P256)

        SK = y * pointX

        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(data["TID"].to_bytes(qL, 'big'))
        m.update(self.pub_key.x.to_bytes(qL, 'big'))
        m.update(self.pub_key.y.to_bytes(qL, 'big'))
        m.update(SK.x.to_bytes(qL, 'big'))
        m.update(SK.y.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        Sig = (y + self.priv_key * int(m.hexdigest(), 16)) % q

        print("Sending Message...")
        # input()

        data = {'TID': self.TID,
                'Y': {
                    'x': Y.x,
                    'y': Y.y
                },
                'Sig': Sig,
                'Pub': {
                    'x': self.pub_key.x,
                    'y': self.pub_key.y
                },
                'TS': TS}
        sendMsgSocket(s, data)

        print("---------------------------------\n")
        ############################

        data = recvMsgSocket(s)
        print("Recieved Message: ")
        print(data)
        print()

        TS = int(datetime.now().timestamp())
        if (abs(TS - data["TS"]) > dT):
            print("Took too long!! Try again.")
            return

        m = hashlib.sha256()
        m.update(SK.x.to_bytes(qL, 'big'))
        m.update(SK.y.to_bytes(qL, 'big'))
        m.update(data["TS"].to_bytes(qL, 'big'))

        if (data["SKV"] != int(m.hexdigest(), 16)):
            print("Incorrect Session Key Verifier!! Try again.")
            return
        
        keys.export_key(SK, curve=curve.P256, filepath='key_SN1_SN2.pub')
        print("Successfully established Session Key.")

    def D2G_initiate(self, conn):
        p = random.randint(1, q)
        TS = int(datetime.now().timestamp())

        m = hashlib.sha256()
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(p.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))

        a = int(m.hexdigest(), 16)
        A = keys.get_public_key(a, curve.P256)

        m = hashlib.sha256()
        m.update(self.priv_key.to_bytes(qL, 'big'))
        m.update(p.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.RID))
        m.update(TS.to_bytes(qL, 'big'))
        x = int(m.hexdigest(), 16)
        m = hashlib.sha256()
        m.update(bytes.fromhex(self.TC))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.RID))
        m.update(TS.to_bytes(qL, 'big'))

        x ^= int(m.hexdigest(), 16)

        m = hashlib.sha256()
        m.update(x.to_bytes(qL, 'big'))
        m.update(self.TID.to_bytes(qL, 'big'))
        m.update(A.x.to_bytes(qL, 'big'))
        m.update(A.y.to_bytes(qL, 'big'))
        m.update(TS.to_bytes(qL, 'big'))
        m.update(bytes.fromhex(self.TC))

        Sig = (a + self.priv_key * int(m.hexdigest(), 16)) % q

        print("Sending Message...")
        input()

        data = {'TID': self.TID,
                'A': {
                    'x': A.x,
                    'y': A.y
                },
                'x': x,
                'Sig': Sig,
                'TS': TS}
        sendMsgConn(conn, data)

        print("---------------------------------\n")
        ############################

        # data = recvMsgConn(conn)
        # print("Recieved Message: ")
        # print(data)
        # print()

        # TS = int(datetime.now().timestamp())
        # if (abs(TS - data["TS"]) > dT):
        #     print("Took too long!! Try again.")
        #     return

        # pointB = point.Point(data["B"]["x"], data["B"]["y"])
        # pointPub = point.Point(data["Pub"]["x"], data["Pub"]["y"])

        # SK = x * pointB

        # m = hashlib.sha256()
        # m.update(data["TID"].to_bytes(qL, 'big'))
        # m.update(self.TID.to_bytes(qL, 'big'))
        # m.update(data["Pub"]["x"].to_bytes(qL, 'big'))
        # m.update(data["Pub"]["y"].to_bytes(qL, 'big'))
        # m.update(SK.x.to_bytes(qL, 'big'))
        # m.update(SK.y.to_bytes(qL, 'big'))
        # m.update(data["TS"].to_bytes(qL, 'big'))

        # if (keys.get_public_key(data["Sig"], curve.P256) != (pointY + int(m.hexdigest(), 16) * pointPub)):
        #     print("Failed to verify Signature! Try again.")
        #     return

        # print("Signature Verified.")

        # print("---------------------------------\n")
        # ############################

        # TS = int(datetime.now().timestamp())
        # m = hashlib.sha256()
        # m.update(SK.x.to_bytes(qL, 'big'))
        # m.update(SK.y.to_bytes(qL, 'big'))
        # m.update(TS.to_bytes(qL, 'big'))

        # SKV = int(m.hexdigest(), 16)

        # print("Sending Message...")
        # input()

        # data = {
        #     'SKV': SKV,
        #     'TS': TS,
        # }
        # sendMsgConn(conn, data)

        # print("Successfully established Session Key.")
