"""The SOCKS5 relay, exercised against a fake upstream.

Written after a real bug: the relay decoded domain targets with the "idna"
codec, which raises when given an `errors` argument, so every connection
addressed by *name* died while IP-addressed ones kept working — a failure that
looked exactly like broken DNS.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import struct
from pathlib import Path

import pytest

SRC = Path(__file__).parents[2] / "containers" / "gateway" / "forwarder.py"
spec = importlib.util.spec_from_file_location("kf_forwarder", SRC)
assert spec and spec.loader
fwd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fwd)

PAYLOAD = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


class FakeUpstream:
    """Minimal SOCKS5 server that records what it was asked for."""

    def __init__(self) -> None:
        self.requests: list[tuple[int, bytes, int]] = []
        self.server: asyncio.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        ver, n = await r.readexactly(2)
        await r.readexactly(n)
        w.write(bytes([5, 0]))
        await w.drain()
        _ver, _cmd, _rsv, atyp = await r.readexactly(4)
        if atyp == 1:
            host = await r.readexactly(4)
        elif atyp == 3:
            host = await r.readexactly((await r.readexactly(1))[0])
        else:
            host = await r.readexactly(16)
        port = struct.unpack("!H", await r.readexactly(2))[0]
        self.requests.append((atyp, host, port))
        w.write(bytes([5, 0, 0, 1]) + b"\x00\x00\x00\x00\x00\x00")
        w.write(PAYLOAD)
        await w.drain()
        w.close()


async def _roundtrip(atyp: int, target: bytes, port: int = 443):
    upstream = FakeUpstream()
    up_port = await upstream.start()
    up = fwd.Upstream("127.0.0.1", up_port, None, None)
    server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
    local_port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == bytes([5, 0])
    if atyp == 3:
        req = bytes([5, 1, 0, atyp, len(target)]) + target
    else:
        req = bytes([5, 1, 0, atyp]) + target
    writer.write(req + struct.pack("!H", port))
    await writer.drain()
    reply = await reader.readexactly(4)
    rest = {1: 6, 3: 0, 4: 18}[reply[3]]
    if rest:
        await reader.readexactly(rest)
    body = await reader.read(len(PAYLOAD))
    writer.close()
    server.close()
    upstream.server.close()  # type: ignore[union-attr]
    return reply, body, upstream.requests


def test_domain_target_relays():
    reply, body, requests = asyncio.run(_roundtrip(3, b"example.com"))
    assert reply[1] == 0, "a hostname CONNECT must succeed"
    assert body == PAYLOAD
    assert requests == [(3, b"example.com", 443)]


def test_internationalised_domain_does_not_crash_the_handler():
    # Already punycoded by the client; nothing here may try to re-decode it.
    reply, body, requests = asyncio.run(_roundtrip(3, b"xn--bcher-kva.example"))
    assert reply[1] == 0
    assert requests[0][1] == b"xn--bcher-kva.example"


def test_ipv4_target_relays_as_ipv4():
    raw = socket.inet_aton("93.184.216.34")
    reply, body, requests = asyncio.run(_roundtrip(1, raw, port=80))
    assert reply[1] == 0
    # Passed through as IPv4, not re-encoded as a numeric "hostname": an
    # upstream is entitled to reject that.
    assert requests == [(1, raw, 80)]


def test_ipv6_target_relays_as_ipv6():
    raw = socket.inet_pton(socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946")
    reply, _body, requests = asyncio.run(_roundtrip(4, raw))
    assert reply[1] == 0
    assert requests == [(4, raw, 443)]


def test_credentials_come_from_a_file_not_the_environment(tmp_path):
    creds = tmp_path / "endpoint.creds"
    creds.write_text("someuser\nsomepass\n")
    assert fwd.read_credentials(str(creds)) == ("someuser", "somepass")


def test_missing_credentials_file_means_no_auth(tmp_path):
    assert fwd.read_credentials(str(tmp_path / "absent")) == (None, None)


def test_empty_credentials_mean_no_auth(tmp_path):
    creds = tmp_path / "c"
    creds.write_text("\n\n")
    assert fwd.read_credentials(str(creds)) == (None, None)


# --------------------------------------------------------------- passthrough
class AuthUpstream:
    """A SOCKS5 server that honours USER_PASS and records the credentials it got."""

    def __init__(self) -> None:
        self.creds: list[tuple[str, str]] = []
        self.server: asyncio.Server | None = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        ver, n = await r.readexactly(2)
        methods = set(await r.readexactly(n))
        if 2 in methods:
            w.write(bytes([5, 2]))
            await w.drain()
            await r.readexactly(1)  # auth ver
            ulen = (await r.readexactly(1))[0]
            user = (await r.readexactly(ulen)).decode()
            plen = (await r.readexactly(1))[0]
            pw = (await r.readexactly(plen)).decode()
            self.creds.append((user, pw))
            w.write(bytes([1, 0]))
            await w.drain()
        else:
            w.write(bytes([5, 0]))
            await w.drain()
        _ver, _cmd, _rsv, atyp = await r.readexactly(4)
        host = (
            await r.readexactly((await r.readexactly(1))[0])
            if atyp == 3
            else await r.readexactly(4 if atyp == 1 else 16)
        )
        await r.readexactly(2)
        del host
        w.write(bytes([5, 0, 0, 1]) + b"\x00\x00\x00\x00\x00\x00" + PAYLOAD)
        await w.drain()
        w.close()


async def _passthrough_roundtrip(up_user, up_pass, mode, client_methods, client_creds):
    upstream = AuthUpstream()
    up_port = await upstream.start()
    up = fwd.Upstream("127.0.0.1", up_port, up_user, up_pass, mode)
    server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
    local_port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    writer.write(bytes([5, len(client_methods)]) + bytes(client_methods))
    await writer.drain()
    chosen = await reader.readexactly(2)
    if chosen[1] == 0xFF:
        writer.close()
        server.close()
        upstream.server.close()  # type: ignore[union-attr]
        return chosen, [], None
    if chosen[1] == 2:
        cu, cp = client_creds
        writer.write(bytes([1, len(cu)]) + cu.encode() + bytes([len(cp)]) + cp.encode())
        await writer.drain()
        assert await reader.readexactly(2) == bytes([1, 0])
    writer.write(bytes([5, 1, 0, 3, len(b"example.com")]) + b"example.com" + struct.pack("!H", 443))
    await writer.drain()
    reply = await reader.readexactly(4)
    await reader.readexactly({1: 6, 3: 0, 4: 18}[reply[3]])
    await reader.read(len(PAYLOAD))
    writer.close()
    server.close()
    upstream.server.close()  # type: ignore[union-attr]
    return chosen, upstream.creds, reply


def test_passthrough_forwards_client_auth_with_the_token_prefix():
    chosen, creds, reply = asyncio.run(
        _passthrough_roundtrip(
            "kf-tok", "profilepw", fwd.PASSTHROUGH, [0, 2], ("example.com", "nonceA")
        )
    )
    assert chosen == bytes([5, 2])
    assert reply[1] == 0
    # The upstream saw the token + the client's username, and the client's password.
    assert creds == [("kf-tok:example.com", "nonceA")]


def test_passthrough_distinct_sites_get_distinct_usernames():
    _c, creds_a, _r = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.PASSTHROUGH, [2], ("a.com", "n"))
    )
    _c, creds_b, _r = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.PASSTHROUGH, [2], ("b.com", "n"))
    )
    assert creds_a[0][0] != creds_b[0][0]


def test_passthrough_same_site_new_nonce_keeps_user_changes_password():
    # New Circuit for this site: same first-party, fresh nonce -> same upstream
    # username (same circuit key) but a different password.
    _c, creds1, _r = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.PASSTHROUGH, [2], ("a.com", "nonce1"))
    )
    _c, creds2, _r = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.PASSTHROUGH, [2], ("a.com", "nonce2"))
    )
    assert creds1[0][0] == creds2[0][0]
    assert creds1[0][1] != creds2[0][1]


def test_passthrough_no_auth_client_uses_the_profile_pair():
    # dnscrypt-proxy and plain Firefox offer only NO_AUTH even in passthrough mode.
    chosen, creds, reply = asyncio.run(
        _passthrough_roundtrip("kf-tok", "profilepw", fwd.PASSTHROUGH, [0], None)
    )
    assert chosen == bytes([5, 0])
    assert creds == [("kf-tok", "profilepw")]


def test_inject_mode_refuses_a_userpass_only_client():
    chosen, _creds, _reply = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.INJECT, [2], ("x", "y"))
    )
    assert chosen == bytes([5, 0xFF])


def test_passthrough_cannot_impersonate_another_bucket():
    # A client username that itself looks like a token still lands behind OUR token.
    _c, creds, _r = asyncio.run(
        _passthrough_roundtrip("kf-tok", "pw", fwd.PASSTHROUGH, [2], ("kf-other:evil", "n"))
    )
    assert creds[0][0].startswith("kf-tok:")


def test_combine_user_folds_over_length():
    long_site = "a" * 300
    folded = fwd.combine_user("kf-tok", long_site)
    assert len(folded.encode()) <= 255
    assert folded == fwd.combine_user("kf-tok", long_site)  # deterministic
    assert folded != fwd.combine_user("kf-tok", "b" * 300)  # distinct inputs differ


@pytest.mark.parametrize("cmd", [2, 3])
def test_bind_and_udp_associate_are_refused(cmd):
    # SOCKS5 UDP is unavailable upstream anyway; refuse rather than hang.
    async def go():
        up = fwd.Upstream("127.0.0.1", 1, None, None)
        server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")
        await reader.readexactly(2)
        writer.write(bytes([5, cmd, 0, 3, 11]) + b"example.com" + struct.pack("!H", 443))
        await writer.drain()
        reply = await reader.readexactly(4)
        writer.close()
        server.close()
        return reply

    assert asyncio.run(go())[1] != 0, "non-CONNECT commands must be refused"


# ------------------------------------------------------------- host listener
async def _guarded_roundtrip(client_methods, client_creds, *, mode=fwd.INJECT):
    """The host listener with a password: the client's credentials are a gate."""
    upstream = AuthUpstream()
    up_port = await upstream.start()
    up = fwd.Upstream("127.0.0.1", up_port, "kf-tok", "exitpw", mode)
    inbound = fwd.Inbound("me", "hunter2")
    server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up, inbound), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(bytes([5, len(client_methods)]) + bytes(client_methods))
    await writer.drain()
    chosen = await reader.readexactly(2)
    status = None
    reply = None
    if chosen[1] == 2:
        cu, cp = client_creds
        writer.write(bytes([1, len(cu)]) + cu.encode() + bytes([len(cp)]) + cp.encode())
        await writer.drain()
        status = await reader.readexactly(2)
        if status == bytes([1, 0]):
            writer.write(bytes([5, 1, 0, 3, 11]) + b"example.com" + struct.pack("!H", 443))
            await writer.drain()
            reply = await reader.readexactly(4)
    writer.close()
    server.close()
    upstream.server.close()  # type: ignore[union-attr]
    return chosen, status, reply, upstream.creds


def test_guarded_host_listener_lets_the_right_password_in():
    chosen, status, reply, creds = asyncio.run(_guarded_roundtrip([0, 2], ("me", "hunter2")))
    assert chosen == bytes([5, 2]) and status == bytes([1, 0]) and reply[1] == 0
    # The gate's credentials never travel upstream; the exit's own pair does.
    assert creds == [("kf-tok", "exitpw")]


def test_guarded_host_listener_refuses_a_wrong_password():
    _chosen, status, reply, creds = asyncio.run(_guarded_roundtrip([2], ("me", "nope")))
    assert status == bytes([1, 1]) and reply is None and creds == []


def test_guarded_host_listener_refuses_a_client_without_credentials():
    chosen, _status, _reply, creds = asyncio.run(_guarded_roundtrip([0], None))
    assert chosen == bytes([5, 0xFF]) and creds == []


def test_guard_wins_over_passthrough():
    # On a guarded listener the credentials are a password, not an isolation key.
    _c, _s, _r, creds = asyncio.run(
        _guarded_roundtrip([2], ("me", "hunter2"), mode=fwd.PASSTHROUGH)
    )
    assert creds == [("kf-tok", "exitpw")]


def test_inbound_without_a_user_is_open():
    assert not fwd.Inbound().authed
    assert not fwd.Inbound().accepts(b"", b"")


def test_credentials_table_picks_the_exit_row(tmp_path):
    table = tmp_path / "credentials"
    table.write_text(
        "# name\tuser\tpass\thost user\thost pass\nse\t\t\t\t\nresi\tu1\tp w\tme\thunter2\n"
    )
    assert fwd.read_table(str(table), "resi") == ("u1", "p w", "me", "hunter2")
    assert fwd.read_table(str(table), "se") == (None, None, None, None)
    assert fwd.read_table(str(table), "absent") == (None, None, None, None)
    assert fwd.read_table(str(tmp_path / "missing"), "se") == (None, None, None, None)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_main_serves_the_member_and_the_host_listener(tmp_path):
    """The real entry point, as the gateway starts it: env and credential files."""
    import os
    import subprocess
    import sys
    import time

    async def scenario() -> tuple[list, bytes, bytes]:
        upstream = AuthUpstream()
        up_port = await upstream.start()
        member, host = _free_port(), _free_port()
        (tmp_path / "up").write_text("kf-tok\nexitpw\n")
        (tmp_path / "host").write_text("me\nhunter2\n")
        env = {
            **os.environ,
            "KF_ENDPOINT_IP": "127.0.0.1",
            "KF_ENDPOINT_PORT": str(up_port),
            "KF_FORWARDER_PORT": str(member),
            "KF_EXPOSE_PORT": str(host),
            "KF_CREDS_FILE": str(tmp_path / "up"),
            "KF_EXPOSE_CREDS_FILE": str(tmp_path / "host"),
        }
        proc = subprocess.Popen([sys.executable, str(SRC)], env=env, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", host), timeout=0.2).close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)

            async def greet(port: int, methods: bytes) -> bytes:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(bytes([5, len(methods)]) + methods)
                await w.drain()
                got = await r.readexactly(2)
                w.close()
                return got

            # members get no-auth; the host listener insists on its password
            return upstream.creds, await greet(member, b"\x00"), await greet(host, b"\x00")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            upstream.server.close()  # type: ignore[union-attr]

    _creds, member_reply, host_reply = asyncio.run(scenario())
    assert member_reply == bytes([5, 0])
    assert host_reply == bytes([5, 0xFF])
