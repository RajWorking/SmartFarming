import json

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