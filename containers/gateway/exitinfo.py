#!/usr/bin/env python3
"""Ask an ip-echo service what the world sees, through this namespace's forwarder.

`podman exec <gateway> kf-exitinfo [URL]` prints the service's JSON body. Run
inside the gateway so it measures every exit the same way, including a provider
exit on the rootless bridge that the host cannot reach. stdlib only.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
from urllib.parse import urlparse

DEFAULT_URL = "https://ifconfig.co/json"


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("forwarder closed the connection")
        buf += chunk
    return buf


def connect(host: str, port: int, timeout: float = 30.0) -> socket.socket:
    forwarder = int(os.environ.get("KF_FORWARDER_PORT", "1080"))
    sock = socket.create_connection(("127.0.0.1", forwarder), timeout=timeout)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise OSError("forwarder refused the greeting")
    name = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big"))
    reply = recv_exact(sock, 4)
    if reply[1] != 0x00:
        raise OSError(f"the exit refused {host}:{port} (code {reply[1]})")
    recv_exact(sock, {0x01: 4, 0x04: 16}.get(reply[3], 0) + 2)
    return sock


def main(argv: list[str]) -> int:
    url = urlparse(argv[1] if len(argv) > 1 else DEFAULT_URL)
    host = url.hostname or ""
    port = url.port or (443 if url.scheme == "https" else 80)
    try:
        sock = connect(host, port)
        if url.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(
            f"GET {url.path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.0\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n".encode()
        )
        raw = b""
        while chunk := sock.recv(65536):
            raw += chunk
        sock.close()
    except OSError as exc:
        print(f"kf-exitinfo: {exc}", file=sys.stderr)
        return 1
    head, _, body = raw.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        body = dechunk(body)
    sys.stdout.write(body.decode("utf-8", "replace"))
    return 0


def dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        size, _, rest = body.partition(b"\r\n")
        n = int(size.split(b";")[0] or b"0", 16)
        if n == 0:
            break
        out += rest[:n]
        body = rest[n + 2 :]
    return out


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
