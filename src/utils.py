import json
from Crypto.Cipher import AES
from fastecdsa import keys, encoding
import hashlib


def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf:
            return None
        buf += newbuf
        count -= len(newbuf)
    return buf


def sendMsg(pipe, msg):
    data = json.dumps(msg).encode()
    sz = len(data)
    pipe.send(sz.to_bytes(4, byteorder='big'))
    pipe.send(data)


def recvMsg(pipe):
    # works with socket s, connection conn
    data = recvall(pipe, 4)
    if not data:
        return
    len = int.from_bytes(data, 'big')
    data = json.loads(recvall(pipe, len).decode())
    return data


def encryptMsg(key_file):
    with open('data.txt', 'rb') as f:
        plain = f.read()
    enc_data = list()
    _, session_key = keys.import_key(key_file)
    session_key = hashlib.sha256(encoding.pem.PEMEncoder.encode_public_key(
        session_key).encode()).digest()
    while len(plain) > 0:
        if len(plain) > 8:
            contents = plain[:8]
        else:
            contents = plain
        plain = plain[len(contents):]
        # print(contents)

        cipher = AES.new(session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(contents)

        data = {
            'nonceLen': len(nonce),
            'ciphertextLen': len(ciphertext),
            'tagLen': len(tag),
            'nonce': int.from_bytes(nonce, "big"),
            'ciphertext': int.from_bytes(ciphertext, "big"),
            'tag': int.from_bytes(tag, "big")
        }

        enc_data.append(data)

    return enc_data


def decryptMsg(data_list, key_file):
    _, session_key = keys.import_key(key_file)
    session_key = hashlib.sha256(encoding.pem.PEMEncoder.encode_public_key(
            session_key).encode()).digest()
    plain = bytes()
    for data in data_list:
        cipher = AES.new(session_key, AES.MODE_EAX,
                        nonce=data["nonce"].to_bytes(data["nonceLen"], "big"))
        contents = cipher.decrypt(
            data["ciphertext"].to_bytes(data["ciphertextLen"], "big"))
        try:
            cipher.verify(data["tag"].to_bytes(data["tagLen"], "big"))
            plain += contents
        except ValueError:
            print("Key incorrect or message corrupted")
    
    with open('data.txt', 'wb') as f:
                f.write(plain)
        
