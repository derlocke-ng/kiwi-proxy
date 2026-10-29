from kiwi_proxy import dns

SAMPLE = """
## google

Google DNS

sdns://AgUAAAAAAAAAAAAOZXhhbXBsZS5pbnZhbGlk

## cloudflare

Cloudflare

sdns://AgcAAAAAAAAAAAAHZXhhbXBsZQ
"""


def test_stamp_parser_handles_the_published_format(monkeypatch):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeResp(SAMPLE.encode()))
    stamps = dns.fetch_stamps()
    assert set(stamps) == {"google", "cloudflare"}
    assert stamps["google"].startswith("sdns://")


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_toml_requires_a_cached_stamp(monkeypatch):
    monkeypatch.setattr(dns, "load_stamps", lambda: {})
    try:
        dns.toml_config("google", blocklist="/b", forwarder="127.0.0.1", forwarder_port=1080)
    except RuntimeError as exc:
        assert "dns sync" in str(exc)
    else:
        raise AssertionError("expected a RuntimeError about the missing stamp")


def test_toml_sends_queries_through_the_forwarder(monkeypatch):
    monkeypatch.setattr(dns, "load_stamps", lambda: {"google": "sdns://x"})
    cfg = dns.toml_config(
        "google",
        blocklist="/blocklist/blocked-names.txt",
        forwarder="127.0.0.1",
        forwarder_port=1080,
    )
    assert "proxy = 'socks5://127.0.0.1:1080'" in cfg
    assert "force_tcp = true" in cfg  # SOCKS5 carries no UDP
    assert f"listen_addresses = ['{dns.LISTEN_ADDR}:53']" in cfg
    assert dns.LISTEN_ADDR == "127.0.0.2"  # 127.0.0.1 is pasta's
    assert "blocked_names_file = '/blocklist/blocked-names.txt'" in cfg
