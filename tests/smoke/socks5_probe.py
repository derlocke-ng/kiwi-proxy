#!/usr/bin/env python3
"""A SOCKS5 client for the gateway smoke test: what a member or host app sees.

    socks5_probe.py relay HOST PORT [USER PASSWORD]
        connect, CONNECT example.com:80 through the proxy, and expect the dummy
        upstream's canned response back: the whole path relays. With USER and
        PASSWORD it offers username/password (a guarded host listener); without,
        no-auth (a member of the namespace).
    socks5_probe.py refused HOST PORT
        offer no-auth only and expect the proxy to refuse it (0xFF): a guarded
        host listener does not let a client without the password in.
    socks5_probe.py dropped HOST PORT
        a plain TCP connect must time out: the destination is outside the one the
        firewall permits, so the SYN never leaves. A refusal means the namespace
        is not sealed.

Exit status 0 when the expectation holds. stdlib only; the member-side run uses
the gateway image's own python3.
"""

from __future__ import annotations

import socket
import struct
import sys

VER = 0x05
NO_AUTH, USER_PASS, NO_ACCEPTABLE = 0x00, 0x02, 0xFF
MARKER = b"kf-smoke: relayed"
TIMEOUT = 10.0


def fail(msg: str) -> int:
    print(f"probe: FAIL {msg}", file=sys.stderr, flush=True)
    return 1


def ok(msg: str) -> int:
    print(f"probe: ok {msg}", flush=True)
    return 0


def read(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"proxy closed after {len(buf)} of {n} bytes")
        buf += chunk
    return buf


def greet(sock: socket.socket, methods: bytes) -> int:
    sock.sendall(bytes([VER, len(methods)]) + methods)
    ver, method = read(sock, 2)
    if ver != VER:
        raise ConnectionError("not a SOCKS5 proxy")
    return method


def relay(host: str, port: int, user: str | None, password: str | None) -> int:
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        if user is not None:
            method = greet(sock, bytes([USER_PASS]))
            if method != USER_PASS:
                return fail(f"offered username/password, proxy chose {method:#x}")
            u, p = user.encode(), (password or "").encode()
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            _ver, status = read(sock, 2)
            if status != 0x00:
                return fail("proxy rejected the password")
        else:
            method = greet(sock, bytes([NO_AUTH]))
            if method != NO_AUTH:
                return fail(f"offered no-auth, proxy chose {method:#x}")
        target = b"example.com"
        sock.sendall(bytes([VER, 0x01, 0x00, 0x03, len(target)]) + target + struct.pack("!H", 80))
        _ver, rep, _rsv, atyp = read(sock, 4)
        if atyp == 0x03:
            read(sock, read(sock, 1)[0] + 2)
        else:
            read(sock, {0x01: 6, 0x04: 18}[atyp])
        if rep != 0x00:
            return fail(f"CONNECT refused with code {rep}")
        body = b""
        while chunk := sock.recv(4096):
            body += chunk
    if MARKER not in body:
        return fail(f"CONNECT succeeded but nothing came back from the upstream: {body!r}")
    return ok(f"relayed through {host}:{port}" + (" with the password" if user else ""))


def refused(host: str, port: int) -> int:
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        method = greet(sock, bytes([NO_AUTH]))
    if method != NO_ACCEPTABLE:
        return fail(f"a client without the password got method {method:#x}, not a refusal")
    return ok(f"{host}:{port} refuses a client without the password")


def dropped(host: str, port: int) -> int:
    try:
        socket.create_connection((host, port), timeout=3.0).close()
    except TimeoutError:
        return ok(f"{host}:{port} is unreachable from the namespace (dropped)")
    except OSError as exc:
        return fail(f"{host}:{port} answered ({exc}): the namespace is not sealed")
    return fail(f"{host}:{port} accepted a connection: the namespace is not sealed")


def main(argv: list[str]) -> int:
    try:
        mode, host, port = argv[0], argv[1], int(argv[2])
        rest = argv[3:]
        if mode == "relay" and len(rest) in (0, 2):
            return relay(host, port, *(rest or (None, None)))
        if mode == "refused" and not rest:
            return refused(host, port)
        if mode == "dropped" and not rest:
            return dropped(host, port)
    except (IndexError, ValueError):
        pass
    except (OSError, ConnectionError) as exc:
        return fail(str(exc))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
