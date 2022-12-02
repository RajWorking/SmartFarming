import random
from fastecdsa import point, keys, encoding
from src.config import *


class ElGamal:

    def encrypt(pubkey_path):
        with open('data.txt') as f:
            message = f.read().encode()
        M = 2 * curve.P256.G  # TODO: encode message to point M

        _, pub = keys.import_key(pubkey_path)
        k = random.randint(1, q)
        K = keys.get_public_key(k, curve.P256)
        C = M + k * pub

        return {
            'K': {
                'x': K.x,
                'y': K.y
            },
            'C': {
                'x': C.x,
                'y': C.y
            },
        }

    def decrypt(data, privkey_path):
        priv, _ = keys.import_key(privkey_path)
        
        K = point.Point(data["K"]["x"], data["K"]["y"])
        C = point.Point(data["C"]["x"], data["C"]["y"])

        contents = encoding.pem.PEMEncoder.encode_public_key(C - priv * K)

        with open('data.txt', 'w') as f:
            f.write(contents)
