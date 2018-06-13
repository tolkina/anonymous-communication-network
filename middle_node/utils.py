import json


def recvall(sock):
    data = b''
    while True:
        t = sock.recv(4096)
        data += t
        if len(t) < 4096:
            break
    return json.loads(data.decode())
