"""kf-exitinfo: the gateway's own fetch through its forwarder (exit measurement,
and the blocklists of a kiwi-server gateway)."""

from __future__ import annotations

import importlib.util
import socket
import threading
from pathlib import Path

import pytest

SRC = Path(__file__).parents[2] / "containers" / "gateway" / "exitinfo.py"
spec = importlib.util.spec_from_file_location("kf_exitinfo", SRC)
assert spec and spec.loader
xi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xi)


def fake_forwarder(response: bytes) -> int:
    """A SOCKS5 server that answers one HTTP request with `response`."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = conn.recv(5)
            conn.recv(head[4] + 2)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.recv(65536)
            conn.sendall(response)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_saves_a_list_atomically(tmp_path, monkeypatch):
    body = b"ads.example\n" * 200
    port = fake_forwarder(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    monkeypatch.setenv("KF_FORWARDER_PORT", str(port))
    out = tmp_path / "list.txt"
    assert xi.main(["kf-exitinfo", "--out", str(out), "http://lists.example/domainswild2"]) == 0
    assert out.read_bytes() == body
    assert not (tmp_path / "list.txt.tmp").exists()


@pytest.mark.parametrize(
    "response",
    [b"HTTP/1.1 404 Not Found\r\n\r\n" + b"x" * 2048, b"HTTP/1.1 200 OK\r\n\r\ntiny"],
)
def test_refuses_an_error_or_a_stub(tmp_path, monkeypatch, response):
    monkeypatch.setenv("KF_FORWARDER_PORT", str(fake_forwarder(response)))
    out = tmp_path / "list.txt"
    out.write_text("previous\n")
    assert xi.main(["kf-exitinfo", "--out", str(out), "http://lists.example/x"]) == 1
    assert out.read_text() == "previous\n"  # a failed fetch keeps the old list


def test_prints_the_exit_info(monkeypatch, capsys):
    body = b'{"ip": "198.51.100.7"}'
    port = fake_forwarder(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\n" + body + b"\r\n0\r\n\r\n"
    )
    monkeypatch.setenv("KF_FORWARDER_PORT", str(port))
    assert xi.main(["kf-exitinfo", "http://ip.example/json"]) == 0
    assert capsys.readouterr().out == body.decode()
