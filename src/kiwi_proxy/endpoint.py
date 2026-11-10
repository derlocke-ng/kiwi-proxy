"""Endpoint parsing and pre-flight. A minimal SOCKS5 client, no dependencies.

Was ``kiwi_fox.core.proxy``; ``ProxyError`` is kept as an alias of ``EndpointError``.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlparse

from .models import Endpoint, ExitInfo

DEFAULT_GEO_URL = "https://ifconfig.co/json"
# Asked in turn when measuring an exit: an ip-echo service may refuse a hosting
# exit (ifconfig.co answers some with an empty 429) that the next one serves.
GEO_URLS = (DEFAULT_GEO_URL, "https://ipinfo.io/json", "https://am.i.mullvad.net/json")
VENDOR_RE = re.compile(r"^(?P<host>[^:]+):(?P<port>\d+)(?::(?P<user>[^:]+):(?P<pw>.+))?$")


class EndpointError(RuntimeError):
    pass


ProxyError = EndpointError


def parse(spec: str) -> tuple[Endpoint, str | None]:
    """Accepts socks5://user:pass@host:port, http(s)://…, and host:port[:user:pass].

    Returns the endpoint plus the password, which the caller must hand to the
    keyring and then forget.
    """
    spec = spec.strip()
    if "://" in spec:
        url = urlparse(spec)
        if url.scheme not in ("socks5", "socks5h", "http", "https"):
            raise EndpointError(f"unsupported scheme {url.scheme!r}")
        if not url.hostname or not url.port:
            raise EndpointError(f"missing host or port in {spec!r}")
        return (
            Endpoint(
                host=url.hostname,
                port=url.port,
                username=url.username,
                has_password=bool(url.password),
            ),
            url.password,
        )
    m = VENDOR_RE.match(spec)
    if not m:
        raise EndpointError(f"cannot parse endpoint {spec!r}")
    return (
        Endpoint(
            host=m["host"],
            port=int(m["port"]),
            username=m["user"],
            has_password=bool(m["pw"]),
        ),
        m["pw"],
    )


def resolve(host: str) -> str:
    """Literal address, resolved on the host. nftables needs an address, and the
    gateway has no DNS before the resolver is up."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError as exc:
        raise EndpointError(f"cannot resolve {host!r}: {exc}") from exc


def _ipv4_of(host: str) -> bytes | None:
    """`host` as 4 bytes: a literal as is, a name resolved on this machine to its
    first IPv4 address; None when there is none (the name is sent instead)."""
    try:
        return socket.inet_aton(host)
    except OSError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return None
    return socket.inet_aton(infos[0][4][0]) if infos else None


def socks5_connect(
    endpoint: Endpoint,
    dest_host: str,
    dest_port: int,
    password: str | None = None,
    timeout: float = 15.0,
) -> socket.socket:
    sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    try:
        if endpoint.username:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05:
            raise EndpointError("not a SOCKS5 server")
        method = resp[1]
        if method == 0x02:
            if not endpoint.username:
                raise EndpointError("proxy demands credentials but none are configured")
            user = endpoint.username.encode()
            pw = (password or "").encode()
            sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(pw)]) + pw)
            auth = _recv_exact(sock, 2)
            if auth[1] != 0x00:
                raise EndpointError("proxy rejected the credentials")
        elif method != 0x00:
            raise EndpointError(f"proxy demands unsupported auth method {method:#x}")
        # By IPv4 where we can: a SOCKS upstream given a name may pick its AAAA
        # record, and the exit the pre-flight reports would then differ from the
        # one the gateway's members get (the forwarder connects by IPv4 too).
        ipv4 = _ipv4_of(dest_host)
        if ipv4:
            sock.sendall(b"\x05\x01\x00\x01" + ipv4 + dest_port.to_bytes(2, "big"))
        else:
            host_bytes = dest_host.encode()
            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + dest_port.to_bytes(2, "big")
            )
        reply = _recv_exact(sock, 4)
        if reply[1] != 0x00:
            raise EndpointError(f"proxy refused the connection (code {reply[1]})")
        atyp = reply[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        return sock
    except Exception:
        sock.close()
        raise


REACH_TIMEOUT = 5.0


def reachable(endpoint: Endpoint, timeout: float = REACH_TIMEOUT) -> None:
    """Raise EndpointError when the proxy itself does not answer: the port
    refuses, nothing comes back within `timeout`, or what answers is not SOCKS5.
    A few milliseconds when it does answer. Asked before a gateway is started, so
    a dead proxy fails at once instead of after every later timeout (measured on
    the VM: 37 to 52 s of resolver wait and echo-service retries)."""
    where = f"{endpoint.host}:{endpoint.port}"
    try:
        sock = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    except TimeoutError as exc:
        raise EndpointError(
            f"the proxy at {where} does not answer (no reply in {timeout:.0f} s)"
        ) from exc
    except ConnectionRefusedError as exc:
        raise EndpointError(f"the proxy at {where} refuses connections") from exc
    except OSError as exc:
        raise EndpointError(
            f"the proxy at {where} cannot be reached: {exc.strerror or exc}"
        ) from exc
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x02\x00\x02" if endpoint.username else b"\x05\x01\x00")
        try:
            reply = sock.recv(2)
        except TimeoutError as exc:
            raise EndpointError(
                f"the proxy at {where} accepts connections but does not answer as SOCKS5 "
                f"(nothing in {timeout:.0f} s)"
            ) from exc
        except OSError as exc:
            raise EndpointError(f"the proxy at {where} dropped the connection: {exc}") from exc
        if not reply:
            raise EndpointError(f"the proxy at {where} closed the connection at once")
        if reply[:1] != b"\x05":
            raise EndpointError(f"what answers at {where} is not a SOCKS5 proxy")
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EndpointError("proxy closed the connection")
        buf += chunk
    return buf


def preflight(
    endpoint: Endpoint, password: str | None = None, geo_url: str = DEFAULT_GEO_URL
) -> ExitInfo:
    """Connect through the endpoint and ask what the world sees."""
    url = urlparse(geo_url)
    host = url.hostname or ""
    port = url.port or (443 if url.scheme == "https" else 80)
    path = url.path or "/"
    sock = socks5_connect(endpoint, host, port, password)
    try:
        if url.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: curl/8.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(req.encode())
        raw = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    finally:
        sock.close()
    _, _, body = raw.partition(b"\r\n\r\n")
    return parse_geo(body.decode("utf-8", "replace"))


def parse_geo(text: str) -> ExitInfo:
    """What an ip-echo service said, as an ExitInfo: the ifconfig.co, ipinfo.io,
    ip-api and am.i.mullvad.net shapes."""
    text = text.strip()
    if text and text[0] not in "{[":  # chunked encoding
        text = "".join(
            line for line in text.splitlines() if line.startswith(("{", "[", '"', " ", "}"))
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EndpointError(f"geo endpoint returned unparseable data: {text[:120]!r}") from exc
    return ExitInfo(
        ip=data.get("ip") or data.get("query") or "",
        country=data.get("country_iso") or data.get("countryCode") or data.get("country"),
        city=data.get("city"),
        timezone=data.get("time_zone") or data.get("timezone"),
        asn=str(data.get("asn") or data.get("as") or data.get("org") or "") or None,
        seen=dt.datetime.now(dt.UTC),
    )
