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


def sendMsgConn(conn, msg):
    data = json.dumps(msg).encode()
    sz = len(data)
    conn.send(sz.to_bytes(4, byteorder='big'))
    conn.send(data)


def recvMsgConn(conn):
    data = recvall(conn, 4)
    if not data:
        return
    len = int.from_bytes(data, 'big')
    data = json.loads(recvall(conn, len).decode())
    return data


def sendMsgSocket(s, msg):
    sz = len(json.dumps(msg).encode())  # length of object
    s.sendall(sz.to_bytes(4, byteorder='big'))
    s.sendall(json.dumps(msg).encode())


def recvMsgSocket(s):
    data = recvall(s, 4)
    if not data:
        return
    len = int.from_bytes(data, 'big')
    data = json.loads(recvall(s, len).decode())
    return data


def sendEncryptMsg(conn, key_file):
    with open('data.txt') as f:
        contents = f.read().encode()

    _, session_key = keys.import_key(key_file)
    session_key = hashlib.sha256(encoding.pem.PEMEncoder.encode_public_key(
        session_key).encode()).digest()

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

    sendMsgConn(conn, data)


def recieveDecryptMsg(s, key_file):
    data = recvMsgSocket(s)

    _, session_key = keys.import_key(key_file)
    session_key = hashlib.sha256(encoding.pem.PEMEncoder.encode_public_key(
        session_key).encode()).digest()

    cipher = AES.new(session_key, AES.MODE_EAX,
                     nonce=data["nonce"].to_bytes(data["nonceLen"], "big"))
    contents = cipher.decrypt(
        data["ciphertext"].to_bytes(data["ciphertextLen"], "big"))
    try:
        cipher.verify(data["tag"].to_bytes(data["tagLen"], "big"))
        with open('data.txt', 'w') as f:
            f.write(contents.decode())
    except ValueError:
        print("Key incorrect or message corrupted")
