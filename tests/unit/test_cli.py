"""The CLI against the real store and a fake podman."""

from __future__ import annotations

import json

import pytest
from test_gateway import FakePodman

from kiwi_proxy import cli, exits, gateway, secrets
from kiwi_proxy.models import Expose


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(gateway.endpoint, "resolve", lambda host: host)
    monkeypatch.setattr(
        gateway.endpoint, "preflight", lambda ep, pw=None: (_ for _ in ()).throw(OSError("offline"))
    )
    return FakePodman(monkeypatch)


@pytest.mark.parametrize(
    ("spec", "bind", "port"),
    [
        ("1081", "127.0.0.1", 1081),
        ("10.8.0.25:1081", "10.8.0.25", 1081),
        ("[::1]:1090", "::1", 1090),
    ],
)
def test_parse_expose(spec, bind, port):
    assert cli.parse_expose(spec) == (bind, port)


@pytest.mark.parametrize("spec", ["", "x", "1.2.3.4:", "70000", "h:0"])
def test_parse_expose_rejects(spec):
    with pytest.raises(ValueError):
        cli.parse_expose(spec)


def test_add_list_show(capsys):
    assert cli.main(["add", "work", "socks5://u:pw@10.64.0.1:1080", "--dns", "remote"]) == 0
    ex = exits.resolve_ref("work")
    assert ex.endpoint.username == "u" and secrets.lookup(ex.id) == "pw"
    assert ex.dns.mode == "remote"
    capsys.readouterr()
    assert cli.main(["list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["name"] == "work" and rows[0]["gateway"] == f"kf-gw-{ex.id[:12]}"
    assert "pw" not in json.dumps(rows)


def test_a_public_host_port_needs_a_password_or_a_yes(capsys, monkeypatch):
    assert cli.main(["add", "lan", "10.64.0.1:1080", "--expose", "0.0.0.0:1081"]) == 1
    assert "expose-user" in capsys.readouterr().err
    assert (
        cli.main(["add", "lan", "10.64.0.1:1080", "--expose", "0.0.0.0:1081", "--expose-open"]) == 0
    )
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("hunter2\n"))
    assert (
        cli.main(
            [
                "add",
                "mesh",
                "10.64.0.1:1080",
                "--expose",
                "10.8.0.25:1082",
                "--expose-user",
                "me",
                "--expose-password-stdin",
            ]  # fmt: skip
        )
        == 0
    )
    ex = exits.resolve_ref("mesh")
    assert ex.expose == Expose(bind="10.8.0.25", port=1082, username="me", has_password=True)
    assert secrets.lookup(ex.id, kind="expose") == "hunter2"


def test_up_holds_and_down_releases(fake, capsys):
    cli.main(["add", "work", "10.64.0.1:1080", "--dns", "remote", "--expose", "1081"])
    ex = exits.resolve_ref("work")
    capsys.readouterr()
    assert cli.main(["up", "work", "--json"]) == 0
    gw = json.loads(capsys.readouterr().out)
    assert gw["name"] == f"kf-gw-{ex.id[:12]}" and gw["network"] == f"container:{gw['name']}"
    assert gw["expose"] == "127.0.0.1:1081"
    assert gateway.held(ex.id)
    assert gateway.release(ex.id) is False  # a consumer finishing leaves it up
    assert cli.main(["down", "work"]) == 0
    assert not gateway.is_up(ex.id)


def test_rm_refuses_another_apps_exit(fake, capsys):
    from kiwi_proxy.models import Endpoint

    exits.create("work", Endpoint(host="h", port=1), owner="kiwi-fox")
    assert cli.main(["rm", "work"]) == 1
    assert "kiwi-fox" in capsys.readouterr().err
    assert cli.main(["rm", "work", "--force"]) == 0
    assert exits.find_by_name("work") is None


def test_socks_auth_flag(capsys):
    cli.main(["add", "tb", "10.64.0.1:1080", "--socks-auth", "passthrough"])
    assert exits.resolve_ref("tb").socks_auth == "passthrough"
    cli.main(["set", "tb", "--socks-auth", "inject"])
    assert exits.resolve_ref("tb").socks_auth == "inject"
