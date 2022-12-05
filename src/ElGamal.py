import random
from fastecdsa import point, keys, encoding
from src.config import *

def sqrt_mod(n, p):
    """
    :param n: int, n must be square root modulo p
    :param p: int, p must be a prime number
    :return:
    """
    # 1. find q and s such that p-1 = q*2**s with q odd
    s = 0
    while True:
        val = pow(2, s, p)
        if (p - 1) % val == 0:
            q = (p - 1) // val
            if q % 2 != 0:
                break
        s += 1

    # 2. Search for z in Zp such that z is quadratic non residue
    z = 2
    while True:
        if pow(z, (p - 1) // 2, p) == (p - 1):
            break
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return r

        i = 1
        while i < m:
            if pow(t, 2 ** i, p) == 1:
                break
            i += 1

        if i == m:
            # n is not square root modulo p
            return -1

        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p


def mtp(m):
    """
        m: int, message as an integer
    """
    x = None
    l = None
    # print(self.p - 1)
    for k in range(30, 51):
        for i in range(k):
            x_dash = m * k + i
            y_dash_sqr = (x_dash ** 3 + a * x_dash + b)
            # print(pow(y_dash_sqr, (self.p - 1) // 2, self.p))
            if pow(y_dash_sqr, (p - 1) // 2, p) == 1:
                x = x_dash
                y = sqrt_mod(y_dash_sqr, p)
                break
                
        if x is not None:
            l = k
            break
    
    if x is None:
        raise ValueError("unencodable point")
    return point.Point(x, y), l


def ptm(pt, l):
    """
        pt: Point, an instance of point.Point
    """
    return pt.x // l

# NOTE: This encryption and decryption scheme cannot handle more than 28(or 29 in some cases) bytes
class ElGamal:

    def encrypt(pubkey_path):
        with open('data.txt', 'rb') as f:
            message = f.read()
        
        enc_data = list()
        while len(message) > 0:
            if len(message) > 8:
                msg = message[:8]
                msg_len = 8
            else:
                msg = message
                msg_len = len(msg)
            message = message[msg_len:]
            # print('msg {}'.format(msg))

            # convert the message into an integer
            msg_int = int.from_bytes(msg, byteorder='big')
            # print('msg_int {}'.format(msg_int))

            # embedd msg len in the msg
            msg_int = msg_int * int(1e6) + msg_len
            # print('msg_int: {}'.format(msg_int))

            # convert the message(in int form) to EC point
            M, l = mtp(msg_int)

            _, pub = keys.import_key(pubkey_path)
            k = random.randint(1, q)
            K = keys.get_public_key(k, curve.P256)
            C = M + k * pub

            enc_data.append({
                'K': {
                    'x': K.x,
                    'y': K.y
                },
                'C': {
                    'x': C.x,
                    'y': C.y,
                },
                'l': l
            })
        return enc_data

    def decrypt(data_list, privkey_path):
        priv, _ = keys.import_key(privkey_path)
        
        plain = bytes()
        for data in data_list:
            K = point.Point(data["K"]["x"], data["K"]["y"])
            C = point.Point(data["C"]["x"], data["C"]["y"])
            l = data['l']

            # contents = encoding.pem.PEMEncoder.encode_public_key(C - priv * K)
            M = C - priv * K

            msg_int = ptm(M, l)

            # print('msg_int {}'.format(msg_int))

            msg_len = msg_int % int(1e6)
            msg_int = msg_int // int(1e6)

            plain += msg_int.to_bytes(msg_len, byteorder='big')
        return plain


        

