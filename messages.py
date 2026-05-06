import json
import socket
from typing import Dict, Any


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = b""

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Socket connection closed unexpectedly")

        data += chunk

    return data


def send_message(sock: socket.socket, obj: Dict[str, Any]):
    data = json.dumps(obj).encode("utf-8")
    length = len(data).to_bytes(4, "big")
    sock.sendall(length + data)


def recv_message(sock: socket.socket) -> Dict[str, Any]:
    length_bytes = recv_exact(sock, 4)
    length = int.from_bytes(length_bytes, "big")
    data = recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))