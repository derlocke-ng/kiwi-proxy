#!/usr/bin/env python3
"""SOCKS5 relay: accepts local connections, adds the upstream's credentials on the
way out.

Firefox prefs cannot authenticate against SOCKS5, and 9proxy's local ports
should have auth on, so this exists to hold the credential where a joined
container cannot read it. It is also the single destination the firewall has to
permit, and the per-exit isolation knob: sending distinct credentials per exit to
a Tor SOCKS port triggers IsolateSOCKSAuth so exits do not share circuits.

Two listeners, one relay:

    127.0.0.1:KF_FORWARDER_PORT   for containers that joined the namespace
    0.0.0.0:KF_EXPOSE_PORT        only when set: what the host publishes. Demands
                                  username/password (RFC 1929) when
                                  KF_EXPOSE_CREDS_FILE names a credentials file

KF_BLOCKLIST names a list of blocked domains (dnscrypt-proxy's bare-name format,
the same file the resolver reads): a CONNECT by name to one of them, or to a name
under one, is refused before anything leaves. Members that resolve through the
gateway's resolver are already covered by it; this covers clients that hand the
name to the proxy instead — socks5h on the host listener. The file is re-read when
it changes, so the daily update reaches a running gateway.

KF_SOCKS_AUTH picks what an unguarded listener does with client credentials:
"inject" (answer no-auth, send the exit's pair) or "passthrough" (Tor Browser:
accept the client's per-site credentials and send them upstream behind the exit's
token). A password-guarded host listener always checks the credentials and then
sends the exit's pair — there they are a gate, not an isolation key.

Credentials arrive as files, never env (`podman inspect` shows env): two lines,
user and password. On a kiwi-server machine, where one rendered file serves every
exit of the host, KF_CREDS_TABLE names a tab-separated table instead and
KF_EXIT_NAME picks the row: name, upstream user, upstream password, host user,
host password.

stdlib only.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

LOG = logging.getLogger("forwarder")

VER = 0x05
NO_AUTH = 0x00
USER_PASS = 0x02
CMD_CONNECT = 0x01
ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 0x01, 0x03, 0x04
REP_OK, REP_GENERAL, REP_NOT_ALLOWED, REP_REFUSED, REP_CMD = 0x00, 0x01, 0x02, 0x05, 0x07


INJECT = "inject"
PASSTHROUGH = "passthrough"


class Blocklist:
    """Blocked domains, re-read when the file changes (checked at most once a
    minute). A missing or unreadable file blocks nothing rather than everything:
    the firewall is the guarantee, this is ad-blocking."""

    RECHECK = 60.0

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.entries: set[str] = set()
        self._mtime: float | None = None
        self._checked = float("-inf")
        self.refresh(force=True)

    def refresh(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._checked < self.RECHECK:
            return
        self._checked = now
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime == self._mtime:
            return
        entries = set()
        try:
            for raw in self.path.read_text(errors="replace").splitlines():
                entry = raw.strip().lower()
                if entry and not entry.startswith(("#", "!")):
                    entries.add(entry.removeprefix("*."))
        except OSError:
            return
        self.entries, self._mtime = entries, mtime
        LOG.info("blocklist: %d names from %s", len(entries), self.path)

    def blocks(self, name: str) -> bool:
        self.refresh()
        labels = name.lower().rstrip(".").split(".")
        return any(".".join(labels[i:]) in self.entries for i in range(len(labels)))


class Upstream:
    def __init__(
        self,
        host: str,
        port: int,
        user: str | None,
        password: str | None,
        mode: str = INJECT,
        blocklist: Blocklist | None = None,
    ) -> None:
        self.host, self.port = host, port
        self.user, self.password = user or None, password or None
        self.mode = mode
        self.blocklist = blocklist

    @property
    def authed(self) -> bool:
        return bool(self.user)


class Inbound:
    """What a client of the guarded host listener must present."""

    def __init__(self, user: str | None = None, password: str | None = None) -> None:
        self.user, self.password = user or None, password or ""

    @property
    def authed(self) -> bool:
        return bool(self.user)

    def accepts(self, user: bytes, password: bytes) -> bool:
        # Both compared, always, in constant time.
        return (
            bool(self.user)
            & hmac.compare_digest(user, (self.user or "").encode())
            & (hmac.compare_digest(password, self.password.encode()))
        )


def combine_user(token: str, client_user: str) -> str:
    """The upstream username for a passthrough connection: the profile token,
    then the client's own SOCKS username (Tor Browser's first-party domain),
    so Tor's IsolateSOCKSAuth keeps a circuit per site while the token still
    isolates profiles. RFC 1929 caps the username at 255 bytes, and the client
    one can be a long domain, so an over-length pair folds to a hash — still
    deterministic (same site -> same circuit) and collision-resistant."""
    combined = f"{token}:{client_user}"
    if len(combined.encode()) <= 255:
        return combined
    return f"{token}:#{hashlib.sha256(client_user.encode()).hexdigest()}"


async def _read(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


def _describe(atyp: int, raw: bytes) -> str:
    """Human-readable target, for logs only — never fed back into the protocol."""
    if atyp == ATYP_IPV4:
        return socket.inet_ntoa(raw)
    if atyp == ATYP_IPV6:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return raw.decode("ascii", "replace")


async def socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user: str | None,
    password: str | None,
) -> None:
    """Negotiate with the upstream as a SOCKS5 client, sending (user, password)."""
    methods = bytes([USER_PASS]) if user else bytes([NO_AUTH])
    writer.write(bytes([VER, len(methods)]) + methods)
    await writer.drain()
    ver, method = await _read(reader, 2)
    if ver != VER:
        raise OSError("upstream is not SOCKS5")
    if method == USER_PASS:
        if not user:
            raise OSError("upstream demands credentials but none are configured")
        u = user.encode()
        p = (password or "").encode()
        writer.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        _, status = await _read(reader, 2)
        if status != 0x00:
            raise OSError("upstream rejected the credentials")
    elif method != NO_AUTH:
        raise OSError(f"upstream demands unsupported auth {method:#x}")


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    """Relay one direction, then propagate the half-close.

    Closing `dst` outright here would tear down the other direction while it is
    still in use; signalling EOF instead lets each side finish and close on its
    own, which is what stops connections accumulating.
    """
    try:
        while chunk := await src.read(65536):
            dst.write(chunk)
            await dst.drain()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        with contextlib.suppress(OSError, NotImplementedError):
            if dst.can_write_eof():
                dst.write_eof()


async def shutdown(*writers: asyncio.StreamWriter) -> None:
    for w in writers:
        with contextlib.suppress(OSError):
            w.close()
    for w in writers:
        with contextlib.suppress(OSError, ConnectionError, asyncio.CancelledError):
            await w.wait_closed()


async def _read_user_pass(reader: asyncio.StreamReader) -> tuple[bytes, bytes] | None:
    """The RFC 1929 sub-negotiation after USER_PASS was chosen. None: malformed."""
    auth_ver = (await _read(reader, 1))[0]
    if auth_ver != 0x01:
        return None
    ulen = (await _read(reader, 1))[0]
    user = await _read(reader, ulen)
    plen = (await _read(reader, 1))[0]
    return user, await _read(reader, plen)


async def handle(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    up: Upstream,
    inbound: Inbound | None = None,
) -> None:
    peer = client_w.get_extra_info("peername")
    try:
        ver, nmethods = await _read(client_r, 2)
        if ver != VER:
            client_w.close()
            return
        offered = set(await _read(client_r, nmethods))
        client_user = client_pass = None
        if inbound is not None and inbound.authed:
            # The host listener, guarded: the credentials are a gate, checked
            # here; the exit's own pair goes upstream.
            if USER_PASS not in offered:
                client_w.write(bytes([VER, 0xFF]))
                await client_w.drain()
                client_w.close()
                return
            client_w.write(bytes([VER, USER_PASS]))
            await client_w.drain()
            got = await _read_user_pass(client_r)
            ok = got is not None and inbound.accepts(*got)
            client_w.write(bytes([0x01, 0x00 if ok else 0x01]))
            await client_w.drain()
            if not ok:
                LOG.warning("rejected host-listener credentials from %s", peer)
                client_w.close()
                return
        elif up.mode == PASSTHROUGH and USER_PASS in offered:
            # Accept the client's SOCKS credentials. They are not a gate here —
            # Tor Browser uses them to key per-first-party circuits, and we carry
            # that through — so any username/password is accepted.
            client_w.write(bytes([VER, USER_PASS]))
            await client_w.drain()
            auth_ver = (await _read(client_r, 1))[0]
            if auth_ver != 0x01:
                client_w.close()
                return
            ulen = (await _read(client_r, 1))[0]
            client_user = (await _read(client_r, ulen)).decode("utf-8", "replace")
            plen = (await _read(client_r, 1))[0]
            client_pass = (await _read(client_r, plen)).decode("utf-8", "replace")
            client_w.write(bytes([0x01, 0x00]))  # auth OK
            await client_w.drain()
        elif NO_AUTH in offered:
            client_w.write(bytes([VER, NO_AUTH]))  # local side needs no auth
            await client_w.drain()
        else:
            # The client offered only USER_PASS and we are not in passthrough:
            # RFC 1928 says answer 0xFF. (Only Tor Browser does this, and it
            # already fails against a NO_AUTH reply, so this just makes it RFC-correct.)
            client_w.write(bytes([VER, 0xFF]))
            await client_w.drain()
            client_w.close()
            return

        # The upstream credentials for this one connection: in passthrough with
        # client credentials, the profile token plus the client's own username
        # (so Tor's per-site isolation survives); otherwise the profile pair.
        if client_user is not None and up.user:
            up_user: str | None = combine_user(up.user, client_user)
            up_password: str | None = client_pass
        else:
            up_user, up_password = up.user, up.password

        ver, cmd, _rsv, atyp = await _read(client_r, 4)
        # Keep the target as bytes and forward it verbatim. Domain names in
        # SOCKS5 are already punycoded ASCII, so there is nothing to decode —
        # and decoding with the "idna" codec raises, because that codec rejects
        # an `errors` argument. That bug closed every connection addressed by
        # name while IP-addressed ones (dnscrypt-proxy's own) kept working,
        # which looked exactly like a DNS fault.
        if atyp == ATYP_IPV4:
            host_bytes = await _read(client_r, 4)
        elif atyp == ATYP_DOMAIN:
            length = (await _read(client_r, 1))[0]
            host_bytes = await _read(client_r, length)
        elif atyp == ATYP_IPV6:
            host_bytes = await _read(client_r, 16)
        else:
            await deny(client_w, REP_GENERAL)
            return
        port = struct.unpack("!H", await _read(client_r, 2))[0]
        host = _describe(atyp, host_bytes)

        if cmd != CMD_CONNECT:
            # No BIND, no UDP ASSOCIATE: SOCKS5 UDP is unavailable upstream anyway.
            await deny(client_w, REP_CMD)
            return

        if atyp == ATYP_DOMAIN and up.blocklist and up.blocklist.blocks(host):
            LOG.debug("blocked %s", host)
            await deny(client_w, REP_NOT_ALLOWED)
            return

        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(up.host, up.port), timeout=20
            )
        except (TimeoutError, OSError) as exc:
            LOG.warning("upstream unreachable: %s", exc)
            await deny(client_w, REP_REFUSED)
            return

        try:
            await socks5_handshake(up_r, up_w, up_user, up_password)
            # Pass the address through in the form the client used, rather than
            # re-encoding everything as a domain: an upstream is entitled to
            # reject a numeric string sent as a hostname.
            if atyp == ATYP_DOMAIN:
                request = bytes([VER, CMD_CONNECT, 0x00, atyp, len(host_bytes)]) + host_bytes
            else:
                request = bytes([VER, CMD_CONNECT, 0x00, atyp]) + host_bytes
            up_w.write(request + struct.pack("!H", port))
            await up_w.drain()
            ver, rep, _rsv, atyp = await _read(up_r, 4)
            if atyp == ATYP_IPV4:
                await _read(up_r, 4 + 2)
            elif atyp == ATYP_DOMAIN:
                length = (await _read(up_r, 1))[0]
                await _read(up_r, length + 2)
            elif atyp == ATYP_IPV6:
                await _read(up_r, 16 + 2)
            if rep != REP_OK:
                LOG.info("upstream refused %s:%s (code %s)", host, port, rep)
                await deny(client_w, rep)
                up_w.close()
                return
        except (OSError, asyncio.IncompleteReadError) as exc:
            LOG.warning("upstream handshake failed: %s", exc)
            await deny(client_w, REP_GENERAL)
            up_w.close()
            return

        client_w.write(bytes([VER, REP_OK, 0x00, ATYP_IPV4]) + b"\x00\x00\x00\x00\x00\x00")
        await client_w.drain()
        try:
            await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))
        finally:
            await shutdown(up_w, client_w)
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    except Exception:
        LOG.exception("relay error for %s", peer)
    finally:
        await shutdown(client_w)


async def deny(writer: asyncio.StreamWriter, code: int) -> None:
    with contextlib.suppress(OSError, ConnectionError):
        writer.write(bytes([VER, code, 0x00, ATYP_IPV4]) + b"\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()


def read_credentials(path: str) -> tuple[str | None, str | None]:
    """0600 file, two lines. Never an env var: `podman inspect` shows env."""
    p = Path(path)
    if not p.exists():
        return None, None
    lines = p.read_text().splitlines()
    user = lines[0].strip() if lines else ""
    password = lines[1] if len(lines) > 1 else ""
    return (user or None), (password or None)


def read_table(path: str, name: str) -> tuple[str | None, str | None, str | None, str | None]:
    """One exit's row of a kiwi-server credentials table: name, upstream user and
    password, host user and password, tab-separated. Missing fields are empty."""
    p = Path(path)
    if not p.exists():
        return None, None, None, None
    for line in p.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = (line.split("\t") + [""] * 5)[:5]
        if fields[0] == name:
            return fields[1] or None, fields[2] or None, fields[3] or None, fields[4] or None
    return None, None, None, None


async def main() -> int:
    logging.basicConfig(level=logging.INFO, format="forwarder: %(message)s", stream=sys.stderr)
    host = os.environ.get("KF_ENDPOINT_IP")
    port = int(os.environ.get("KF_ENDPOINT_PORT", "0"))
    listen_port = int(os.environ.get("KF_FORWARDER_PORT", "1080"))
    creds = os.environ.get("KF_CREDS_FILE", "/run/kf/endpoint.creds")
    mode = os.environ.get("KF_SOCKS_AUTH", INJECT)
    expose_port = int(os.environ.get("KF_EXPOSE_PORT", "") or 0)
    if not host or not port:
        LOG.error("KF_ENDPOINT_IP and KF_ENDPOINT_PORT are required")
        return 2
    if mode not in (INJECT, PASSTHROUGH):
        LOG.error("KF_SOCKS_AUTH must be %r or %r, got %r", INJECT, PASSTHROUGH, mode)
        return 2
    table = os.environ.get("KF_CREDS_TABLE")
    if table:
        user, password, in_user, in_password = read_table(table, os.environ.get("KF_EXIT_NAME", ""))
    else:
        user, password = read_credentials(creds)
        in_user, in_password = read_credentials(os.environ.get("KF_EXPOSE_CREDS_FILE", ""))
    if mode == PASSTHROUGH and not user:
        # Passthrough always prepends the profile token; without one a client
        # could land in any bucket, so refuse to start rather than isolate nothing.
        LOG.error("passthrough mode needs a profile token in the credentials file")
        return 2
    blocklist = Blocklist(os.environ["KF_BLOCKLIST"]) if os.environ.get("KF_BLOCKLIST") else None
    up = Upstream(host, port, user, password, mode, blocklist)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, up), "127.0.0.1", listen_port, reuse_address=True
    )
    LOG.info(
        "listening on 127.0.0.1:%s -> %s:%s (%s, %s)",
        listen_port,
        host,
        port,
        "authenticated" if up.authed else "no auth",
        mode,
    )
    servers = [server]
    if expose_port:
        inbound = Inbound(in_user, in_password)
        servers.append(
            await asyncio.start_server(
                lambda r, w: handle(r, w, up, inbound), "0.0.0.0", expose_port, reuse_address=True
            )
        )
        LOG.info(
            "host listener on 0.0.0.0:%s (%s)",
            expose_port,
            "password required" if inbound.authed else "no password",
        )
    await asyncio.gather(*(s.serve_forever() for s in servers))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
