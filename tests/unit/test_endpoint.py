import pytest

from kiwi_proxy.endpoint import EndpointError, ProxyError, parse, parse_geo, resolve


@pytest.mark.parametrize(
    ("spec", "host", "port", "user", "has_pw"),
    [
        ("socks5://1.2.3.4:1080", "1.2.3.4", 1080, None, False),
        ("socks5://u:p@1.2.3.4:1080", "1.2.3.4", 1080, "u", True),
        ("socks5h://u:p@host.example:9050", "host.example", 9050, "u", True),
        ("http://proxy:8080", "proxy", 8080, None, False),
        ("10.64.0.1:1080", "10.64.0.1", 1080, None, False),
        ("1.2.3.4:9050:user:sec:ret", "1.2.3.4", 9050, "user", True),
    ],
)
def test_parse(spec, host, port, user, has_pw):
    ep, pw = parse(spec)
    assert (ep.host, ep.port, ep.username) == (host, port, user)
    assert bool(pw) is has_pw
    assert ep.has_password is has_pw


def test_password_is_not_stored_on_the_endpoint():
    ep, pw = parse("socks5://u:topsecret@1.2.3.4:1080")
    assert "topsecret" not in ep.model_dump_json()
    assert pw == "topsecret"


@pytest.mark.parametrize("spec", ["", "nonsense", "ftp://h:21", "host:notaport", "socks5://h"])
def test_parse_rejects(spec):
    with pytest.raises(EndpointError):
        parse(spec)


def test_resolve_passes_literals_through():
    assert resolve("10.64.0.1") == "10.64.0.1"


def test_resolve_rejects_garbage():
    with pytest.raises(EndpointError):
        resolve("no-such-host.invalid")


def test_proxyerror_is_the_old_name_of_endpointerror():
    # kiwi-fox caught proxy.ProxyError; the alias keeps that working after the split.
    assert ProxyError is EndpointError


def test_parse_geo_reads_ifconfig_and_ip_api_shapes():
    info = parse_geo('{"ip": "203.0.113.9", "country_iso": "DE", "city": "Berlin", "asn": "AS1"}')
    assert (info.ip, info.country, info.city, info.asn) == ("203.0.113.9", "DE", "Berlin", "AS1")
    info = parse_geo('{"query": "198.51.100.4", "countryCode": "SE", "as": "AS2 x"}')
    assert (info.ip, info.country) == ("198.51.100.4", "SE")


def test_parse_geo_reads_the_ipinfo_shape():
    info = parse_geo(
        '{"ip": "148.251.177.170", "country": "DE", "city": "Falkenstein", "org": "AS24940 Hetzner"}'
    )
    assert (info.ip, info.country, info.city, info.asn) == (
        "148.251.177.170",
        "DE",
        "Falkenstein",
        "AS24940 Hetzner",
    )


def test_parse_geo_rejects_garbage():
    with pytest.raises(EndpointError):
        parse_geo("<html>nope</html>")


def _fake_socks5(replies: list) -> int:
    """A SOCKS5 server on the loopback that records one CONNECT request."""
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = conn.recv(4)
            if head[3] == 0x01:
                rest = conn.recv(4 + 2)
            else:
                n = conn.recv(1)[0]
                rest = conn.recv(n + 2)
            replies.append((head[3], rest[:-2]))
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_socks5_connect_asks_by_ipv4_when_the_name_has_one(monkeypatch):
    import socket

    from kiwi_proxy import endpoint
    from kiwi_proxy.models import Endpoint

    seen: list = []
    port = _fake_socks5(seen)
    monkeypatch.setattr(endpoint, "_ipv4_of", lambda host: socket.inet_aton("203.0.113.9"))
    endpoint.socks5_connect(Endpoint(host="127.0.0.1", port=port), "ifconfig.co", 443).close()
    assert seen == [(0x01, socket.inet_aton("203.0.113.9"))]  # IPv4, not the name


def test_socks5_connect_falls_back_to_the_name(monkeypatch):
    from kiwi_proxy import endpoint
    from kiwi_proxy.models import Endpoint

    seen: list = []
    port = _fake_socks5(seen)
    monkeypatch.setattr(endpoint, "_ipv4_of", lambda host: None)
    endpoint.socks5_connect(Endpoint(host="127.0.0.1", port=port), "onion.example", 80).close()
    assert seen == [(0x03, b"onion.example")]
