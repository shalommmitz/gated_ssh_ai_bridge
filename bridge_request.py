#!/usr/bin/env python3
import json
import os
import socket
import sys


DEFAULT_HOST = os.environ.get("SSH_BRIDGE_HOST", "host.docker.internal")
DEFAULT_PORT = int(os.environ.get("SSH_BRIDGE_PORT", "8765"))
CONNECT_TIMEOUT = float(os.environ.get("SSH_BRIDGE_CONNECT_TIMEOUT", "5"))
WAIT_TIMEOUT = float(os.environ.get("SSH_BRIDGE_WAIT_TIMEOUT", "600"))


def read_response(sock):
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    return b"".join(chunks).decode()


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: bridge_request.py COMMAND PURPOSE RISK")

    command = sys.argv[1]
    if command.startswith("@"):
        with open(command[1:], "r", encoding="utf-8") as f:
            command = f.read().strip()

    request = {"command": command, "purpose": sys.argv[2], "risk": sys.argv[3]}
    wait_timeout = None if WAIT_TIMEOUT <= 0 else WAIT_TIMEOUT
    with socket.create_connection((DEFAULT_HOST, DEFAULT_PORT), timeout=CONNECT_TIMEOUT) as sock:
        sock.settimeout(wait_timeout)
        sock.sendall((json.dumps(request) + "\n").encode())
        print(read_response(sock), end="")


if __name__ == "__main__":
    main()
