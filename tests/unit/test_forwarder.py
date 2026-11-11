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


def test_main_without_a_host_listener_comes_up(tmp_path):
    """Every kiwi-fox gateway: no KF_EXPOSE_PORT, no KF_EXPOSE_CREDS_FILE. The
    forwarder read the empty credentials path as the current directory and died
    before listening, which took the gateway — and every browser — down at start."""
    import os
    import subprocess
    import sys
    import time

    async def scenario() -> tuple[bool, bytes, bytes]:
        upstream = AuthUpstream()
        up_port = await upstream.start()
        member = _free_port()
        (tmp_path / "up").write_text("kf-tok\nexitpw\n")
        env = {
            **os.environ,
            "KF_ENDPOINT_IP": "127.0.0.1",
            "KF_ENDPOINT_PORT": str(up_port),
            "KF_FORWARDER_PORT": str(member),
            "KF_CREDS_FILE": str(tmp_path / "up"),
        }
        env.pop("KF_EXPOSE_PORT", None)
        env.pop("KF_EXPOSE_CREDS_FILE", None)
        proc = subprocess.Popen([sys.executable, str(SRC)], env=env, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and proc.poll() is None:
                try:
                    socket.create_connection(("127.0.0.1", member), timeout=0.2).close()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            alive = proc.poll() is None
            if not alive:
                return False, b"", proc.stderr.read()  # type: ignore[union-attr]
            r, w = await asyncio.open_connection("127.0.0.1", member)
            w.write(bytes([5, 1, 0]))
            await w.drain()
            got = await r.readexactly(2)
            w.close()
            return True, got, b""
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            upstream.server.close()  # type: ignore[union-attr]

    alive, reply, stderr = asyncio.run(scenario())
    assert alive, stderr.decode(errors="replace")
    assert reply == bytes([5, 0])


# ------------------------------------------------------------------ blocklist
def _blocklist(tmp_path, text="# oisd\nads.example\n*.tracker.example\n\n"):
    path = tmp_path / "blocked-names.txt"
    path.write_text(text)
    return fwd.Blocklist(str(path))


def test_blocklist_uses_the_bare_name_rule(tmp_path):
    bl = _blocklist(tmp_path)
    assert bl.blocks("ads.example") and bl.blocks("deep.sub.ads.example")
    assert bl.blocks("ADS.Example.") and bl.blocks("x.tracker.example")
    assert not bl.blocks("notads.example") and not bl.blocks("example")


def test_blocklist_follows_the_file(tmp_path, monkeypatch):
    import os

    bl = _blocklist(tmp_path)
    (tmp_path / "blocked-names.txt").write_text("other.example\n")
    os.utime(tmp_path / "blocked-names.txt", (1, 1))  # a different mtime, whatever the clock
    monkeypatch.setattr(fwd.Blocklist, "RECHECK", 0.0)
    assert bl.blocks("other.example") and not bl.blocks("ads.example")


def test_a_missing_blocklist_blocks_nothing(tmp_path):
    assert not fwd.Blocklist(str(tmp_path / "absent")).blocks("ads.example")


def test_the_same_rule_as_the_host_side_matcher(tmp_path):
    from kiwi_proxy import dns

    bl = _blocklist(tmp_path)
    for name in ("ads.example", "a.ads.example", "notads.example", "tracker.example"):
        assert bl.blocks(name) == dns.blocked(name, bl.entries), name


def test_a_blocked_name_is_refused_before_anything_leaves(tmp_path):
    async def go():
        upstream = FakeUpstream()
        up_port = await upstream.start()
        up = fwd.Upstream("127.0.0.1", up_port, None, None, blocklist=_blocklist(tmp_path))
        server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def connect(target: bytes, atyp: int = 3) -> int:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x05\x01\x00")
            await r.readexactly(2)
            head = bytes([5, 1, 0, atyp]) + (bytes([len(target)]) if atyp == 3 else b"")
            w.write(head + target + struct.pack("!H", 443))
            await w.drain()
            reply = await r.readexactly(4)
            w.close()
            return reply[1]

        codes = (
            await connect(b"pixel.ads.example"),
            await connect(b"wikipedia.org"),
            await connect(socket.inet_aton("93.184.216.34"), atyp=1),  # names only
        )
        server.close()
        upstream.server.close()  # type: ignore[union-attr]
        return codes, upstream.requests

    (blocked, allowed, by_ip), requests = asyncio.run(go())
    assert blocked == fwd.REP_NOT_ALLOWED
    assert allowed == 0 and by_ip == 0
    assert [r[1] for r in requests] == [b"wikipedia.org", socket.inet_aton("93.184.216.34")]


def test_read_credentials_with_no_path_means_no_credentials(tmp_path):
    # A gateway without a host listener runs with KF_EXPOSE_CREDS_FILE unset. The
    # empty path is the current directory; reading it raised IsADirectoryError and
    # took every gateway down at start.
    assert fwd.read_credentials("") == (None, None)
    assert fwd.read_credentials(str(tmp_path)) == (None, None)


def test_dns_query_and_first_a_round_trip():
    q = fwd.dns_query("ifconfig.co")
    assert q[:2] == b"\x4b\x46" and q.endswith(b"\x08ifconfig\x02co\x00\x00\x01\x00\x01")
    # an answer: the question echoed, one CNAME then one A, as resolvers send them
    header = struct.pack("!HHHHHH", 0x4B46, 0x8180, 1, 2, 0, 0)
    question = q[12:]
    cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 3) + b"\x01x\x00"
    a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.9")
    assert fwd.dns_first_a(header + question + cname + a) == "203.0.113.9"
    nx = struct.pack("!HHHHHH", 0x4B46, 0x8183, 1, 0, 0, 0) + question
    assert fwd.dns_first_a(nx) is None  # NXDOMAIN
    assert (
        fwd.dns_first_a(struct.pack("!H", 0x1111) + header[2:] + question + a) is None
    )  # not ours


async def _roundtrip_resolving(resolver: str | None, answer: str | None, monkeypatch):
    upstream = FakeUpstream()
    up_port = await upstream.start()
    asked = []

    async def fake_resolve(name, server, timeout=5.0):
        asked.append((name, server))
        return answer

    monkeypatch.setattr(fwd, "resolve_a", fake_resolve)
    up = fwd.Upstream("127.0.0.1", up_port, None, None, resolver=resolver)
    server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(bytes([5, 1, 0]))
    await w.drain()
    assert await r.readexactly(2) == bytes([5, 0])
    name = b"ifconfig.co"
    w.write(bytes([5, 1, 0, 3, len(name)]) + name + struct.pack("!H", 443))
    await w.drain()
    reply = await r.readexactly(10)
    body = await r.read() if reply[1] == 0 else b""
    w.close()
    server.close()
    await server.wait_closed()
    upstream.server.close()
    return reply[1], body, upstream.requests, asked


def test_resolver_mode_connects_the_upstream_by_ipv4(monkeypatch):
    rep, body, requests, asked = asyncio.run(
        _roundtrip_resolving("127.0.0.2", "203.0.113.9", monkeypatch)
    )
    assert rep == 0 and body == PAYLOAD
    assert requests == [(1, socket.inet_aton("203.0.113.9"), 443)]  # IPv4, not the name
    assert asked == [("ifconfig.co", "127.0.0.2")]  # asked of the gateway resolver


def test_resolver_mode_refuses_a_name_without_an_a_record(monkeypatch):
    rep, _body, requests, _asked = asyncio.run(_roundtrip_resolving("127.0.0.2", None, monkeypatch))
    assert rep == fwd.REP_HOST_UNREACH and requests == []


def test_remote_mode_still_passes_the_name_through(monkeypatch):
    rep, body, requests, asked = asyncio.run(_roundtrip_resolving(None, "203.0.113.9", monkeypatch))
    assert rep == 0 and body == PAYLOAD
    assert requests == [(3, b"ifconfig.co", 443)] and asked == []


# ------------------------------------------------------------ control filter
@pytest.mark.parametrize(
    ("line", "action", "starts"),
    [
        ("PROTOCOLINFO 1\r\n", "reply", "250-PROTOCOLINFO"),
        ('AUTHENTICATE "anything"\r\n', "reply", "250 OK"),
        ("TAKEOWNERSHIP\r\n", "reply", "250 OK"),
        ("SETCONF DisableNetwork=0\r\n", "reply", "250 OK"),
        ("SIGNAL NEWNYM\r\n", "pass", "SIGNAL NEWNYM"),
        ("SIGNAL HALT\r\n", "reply", "510"),
        ("GETINFO version circuit-status\r\n", "pass", "GETINFO"),
        ("GETINFO ns/id/ABCD ip-to-country/1.2.3.4\r\n", "pass", "GETINFO"),
        ("GETINFO config-text\r\n", "reply", "552"),
        ("GETINFO net/listeners/socks\r\n", "reply", '250-net/listeners/socks="127.0.0.1:1080"'),
        ("GETCONF UseBridges\r\n", "pass", "GETCONF"),
        ("GETCONF HashedControlPassword\r\n", "reply", "552"),
        ("SETCONF ExitNodes={us}\r\n", "reply", "510"),
        ("SETEVENTS STREAM CIRC ADDRMAP\r\n", "pass", "SETEVENTS STREAM CIRC\r\n"),
        ("ONION_CLIENT_AUTH_ADD abc.onion x25519:KEY\r\n", "pass", "ONION_CLIENT_AUTH_ADD"),
        ("ADD_ONION NEW:BEST Port=80\r\n", "reply", "510"),
        ("MAPADDRESS 1.2.3.4=evil.example\r\n", "reply", "510"),
    ],
)
def test_the_control_filter_lets_through_only_what_tor_browser_needs(line, action, starts):
    got_action, out = fwd.control_decide(line, 1080)
    assert got_action == action and out.startswith(starts), out


@pytest.mark.parametrize(
    ("line", "note"),
    [
        ("SIGNAL NEWNYM\r\n", "control: new identity (SIGNAL NEWNYM)"),
        ("GETINFO config-text\r\n", "control: refused GETINFO config-text"),
        ("GETCONF HashedControlPassword\r\n", "control: refused GETCONF HashedControlPassword"),
        ("SETCONF ExitNodes={us}\r\n", "control: refused SETCONF"),
        ("ADD_ONION ED25519-V3:SECRETKEY Port=80\r\n", "control: refused ADD_ONION"),
        ("GETINFO version\r\n", None),
        ("ONION_CLIENT_AUTH_ADD abc.onion x25519:KEY\r\n", None),
        ('AUTHENTICATE "x"\r\n', None),
    ],
)
def test_the_control_filter_logs_new_identity_and_refusals_without_arguments(line, note):
    action, out = fwd.control_decide(line, 1080)
    assert fwd.control_note(line, action, out) == note


# ----------------------------------------- Tor Browser's own SOCKS usernames back
def test_events_name_tor_browsers_own_socks_username_without_the_exit_token():
    tok = "kf-exit-0123"
    line = (
        b'650 STREAM 42 SUCCEEDED 7 1.2.3.4:443 SOCKS_USERNAME="kf-exit-0123:example.com:0" '
        b'SOCKS_PASSWORD="nonce"\r\n'
    )
    assert fwd.control_unprefix(line, tok) == (
        b'650 STREAM 42 SUCCEEDED 7 1.2.3.4:443 SOCKS_USERNAME="example.com:0" '
        b'SOCKS_PASSWORD="nonce"\r\n'
    )
    circ = b'650 CIRC 7 BUILT $A~a,$B~b,$C~c SOCKS_USERNAME="kf-exit-0123:x.org:0"\r\n'
    assert b'SOCKS_USERNAME="x.org:0"' in fwd.control_unprefix(circ, tok)
    other = b'650 STREAM 9 SUCCEEDED 3 1.2.3.4:80 SOCKS_USERNAME="someone-else:a"\r\n'
    assert fwd.control_unprefix(other, tok) == other
    assert fwd.control_unprefix(b"250 OK\r\n", tok) == b"250 OK\r\n"


def test_a_folded_long_username_comes_back_whole():
    tok = "kf-exit-0123"
    long_user = "a" * 250 + '.example"x'
    sent = fwd.combine_user(tok, long_user)
    assert sent.startswith(tok + ":#") and len(sent.encode()) <= 255
    line = f'650 STREAM 1 SUCCEEDED 2 1.2.3.4:443 SOCKS_USERNAME="{sent}"\r\n'.encode()
    back = fwd.control_unprefix(line, tok)
    assert back == (
        b'650 STREAM 1 SUCCEEDED 2 1.2.3.4:443 SOCKS_USERNAME="' + b"a" * 250 + b'.example\\"x"\r\n'
    )


def test_the_control_relay_rewrites_what_tor_sends_line_by_line():
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(b'650 STREAM 1 NEW 0 x:443 SOCKS_USERNAME="tok:site:0"\r\n250 OK\r\n')
        reader.feed_eof()
        out = bytearray()

        class W:
            def write(self, b):
                out.extend(b)

            async def drain(self):
                pass

            def can_write_eof(self):
                return False

        await fwd.control_relay(reader, W(), "tok")
        return bytes(out)

    assert asyncio.run(go()) == b'650 STREAM 1 NEW 0 x:443 SOCKS_USERNAME="site:0"\r\n250 OK\r\n'


# --------------------------------------------- direct: a tunnel exit (a VPN)
async def _direct_roundtrip(monkeypatch, *, by_name: bool, answer: str | None = "127.0.0.1"):
    async def echo(r, w):
        w.write(b"hello " + await r.read(5))
        await w.drain()
        w.close()

    target = await asyncio.start_server(echo, "127.0.0.1", 0)
    tport = target.sockets[0].getsockname()[1]
    asked = []

    async def fake_resolve(name, server, timeout=5.0):
        asked.append((name, server))
        return answer

    monkeypatch.setattr(fwd, "resolve_a", fake_resolve)
    up = fwd.Upstream("", 0, None, None, resolver="127.0.0.2", direct=True)
    server = await asyncio.start_server(lambda r, w: fwd.handle(r, w, up), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(bytes([5, 1, 0]))
    await w.drain()
    assert await r.readexactly(2) == bytes([5, 0])
    if by_name:
        name = b"svc.example"
        w.write(bytes([5, 1, 0, 3, len(name)]) + name + struct.pack("!H", tport))
    else:
        w.write(bytes([5, 1, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", tport))
    await w.drain()
    reply = await r.readexactly(10)
    body = b""
    if reply[1] == 0:
        w.write(b"world")
        await w.drain()
        body = await r.read()
    w.close()
    server.close()
    target.close()
    return reply[1], body, asked


def test_direct_mode_connects_the_target_itself_names_through_the_resolver(monkeypatch):
    rep, body, asked = asyncio.run(_direct_roundtrip(monkeypatch, by_name=True))
    assert rep == 0 and body == b"hello world"
    assert asked == [("svc.example", "127.0.0.2")]


def test_direct_mode_takes_an_address_as_it_is(monkeypatch):
    rep, body, asked = asyncio.run(_direct_roundtrip(monkeypatch, by_name=False))
    assert rep == 0 and body == b"hello world" and asked == []


def test_direct_mode_refuses_a_name_the_resolver_does_not_know(monkeypatch):
    rep, _body, _asked = asyncio.run(_direct_roundtrip(monkeypatch, by_name=True, answer=None))
    assert rep == fwd.REP_HOST_UNREACH
