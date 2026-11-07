#!/usr/bin/env python3
"""A SOCKS5 upstream for the gateway smoke test: stands in for the exit.

It demands username/password (RFC 1929) and checks them against the pair given
on the command line, which is the pair the gateway's credentials secret holds —
so a gateway that never read its secret cannot relay through it. Every CONNECT
it accepts is answered with a canned HTTP response and closed, so the probe on
the other side can tell a relayed connection from anything else without a real
target. Each request is logged, so a failed run shows what arrived.

    socks5_dummy.py PORT USER PASSWORD

stdlib only, like the forwarder; it runs from the gateway image's own python3.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import sys

VER = 0x05
NO_ACCEPTABLE = 0xFF
USER_PASS = 0x02
CMD_CONNECT = 0x01
ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 0x01, 0x03, 0x04
REP_OK, REP_GENERAL, REP_CMD = 0x00, 0x01, 0x07

PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nkf-smoke: relayed"


def log(msg: str) -> None:
    print(f"dummy: {msg}", file=sys.stderr, flush=True)


class Handler(socketserver.StreamRequestHandler):
    user: bytes = b""
    password: bytes = b""

    def _read(self, n: int) -> bytes:
        data = self.rfile.read(n)
        if len(data) != n:
            raise ConnectionError("client closed early")
        return data

    def handle(self) -> None:
        try:
            self._handle()
        except ConnectionError as exc:
            log(f"{self.client_address}: {exc}")

    def _handle(self) -> None:
        ver, nmethods = self._read(2)
        methods = self._read(nmethods)
        if ver != VER or USER_PASS not in methods:
            log(f"{self.client_address}: offered no username/password, refused")
            self.wfile.write(bytes([VER, NO_ACCEPTABLE]))
            return
        self.wfile.write(bytes([VER, USER_PASS]))
        auth_ver, ulen = self._read(2)
        user = self._read(ulen)
        plen = self._read(1)[0]
        password = self._read(plen)
        ok = auth_ver == 0x01 and user == self.user and password == self.password
        self.wfile.write(bytes([0x01, 0x00 if ok else 0x01]))
        if not ok:
            log(f"{self.client_address}: wrong credentials {user!r}, refused")
            return
        ver, cmd, _rsv, atyp = self._read(4)
        if atyp == ATYP_IPV4:
            target = socket.inet_ntoa(self._read(4))
        elif atyp == ATYP_DOMAIN:
            target = self._read(self._read(1)[0]).decode("ascii", "replace")
        elif atyp == ATYP_IPV6:
            target = socket.inet_ntop(socket.AF_INET6, self._read(16))
        else:
            self.wfile.write(bytes([VER, REP_GENERAL, 0x00, ATYP_IPV4]) + bytes(6))
            return
        port = struct.unpack("!H", self._read(2))[0]
        if cmd != CMD_CONNECT:
            log(f"{self.client_address}: command {cmd:#x}, refused")
            self.wfile.write(bytes([VER, REP_CMD, 0x00, ATYP_IPV4]) + bytes(6))
            return
        log(f"{self.client_address}: CONNECT {target}:{port} with the right credentials")
        self.wfile.write(bytes([VER, REP_OK, 0x00, ATYP_IPV4]) + bytes(6) + PAYLOAD)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    port, user, password = int(argv[0]), argv[1], argv[2]
    Handler.user, Handler.password = user.encode(), password.encode()
    with Server(("0.0.0.0", port), Handler) as server:
        log(f"listening on 0.0.0.0:{port}, expecting user {user!r}")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
