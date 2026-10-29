"""The kiwi-server module, rendered by kiwi-server's own renderer (kiwimodules).

Needs a kiwi-server (or kiwi-modules) checkout: KIWI_SERVER_SRC, or one beside this
repository. Skipped without it, so CI without kiwi-server still runs everything else.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "server-module" / "kiwi-proxy"


def _find_kiwi_server() -> Path | None:
    env = os.environ.get("KIWI_SERVER_SRC")
    candidates = [Path(env)] if env else []
    candidates += [ROOT.parent / "kiwi-server", ROOT.parent / "derlocke-ng" / "kiwi-server"]
    for c in candidates:
        if (c / "lib" / "kiwimodules" / "modules.py").exists() and (c / "modules").is_dir():
            return c
    return None


SERVER = _find_kiwi_server()
pytestmark = pytest.mark.skipif(SERVER is None, reason="no kiwi-server checkout beside this repo")

MACHINE = """
name: sh3
domain: home
target: debian
timezone: Europe/Berlin
admin: {{ user: kiwi }}
role: node
node:
  preset: minimal
  vpn_ip: 10.8.0.25
  modules: [vpn-client, tor, kiwi-proxy]
  kiwi-proxy:
    exits:
{exits}
seed: seed
"""

EXITS = """      se: { host: 10.64.0.1, port: 1080, expose: 1081 }
      resi: { host: proxy.example.net, port: 1080, username: u1, password: "p w", expose: 1082, expose_user: me, expose_password: hunter2 }
      tor: { via: tor, port: 9050, expose: 1083 }"""


def render(tmp_path, monkeypatch, exits=EXITS):
    pytest.importorskip("jinja2")
    pytest.importorskip("yaml")
    modules = tmp_path / "modules"
    shutil.copytree(SERVER / "modules", modules)
    shutil.copytree(MODULE, modules / "kiwi-proxy")
    (tmp_path / "secrets").mkdir()
    wg = "[Interface]\nPrivateKey = x\nAddress = 10.8.0.25/32\n[Peer]\nPublicKey = y\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.8.0.0/16\n"
    (tmp_path / "secrets" / "sh3.home.conf").write_text(wg)
    (tmp_path / "seed").write_bytes(b"s" * 32)
    machine = tmp_path / "sh3.yaml"
    machine.write_text(MACHINE.format(exits=exits))
    monkeypatch.setenv("KIWI_MODULES_HOME", str(modules))
    monkeypatch.setenv("KIWI_SERVER_ROLES", str(SERVER / "roles"))
    monkeypatch.syspath_prepend(str(SERVER / "lib"))
    for name in [m for m in sys.modules if m.startswith("kiwimodules")]:
        del sys.modules[name]
    from kiwimodules import cli as kcli

    out = tmp_path / "out"
    code = kcli.main(["render", str(machine), "-o", str(out)])
    return code, out


def test_one_sealed_gateway_per_exit(tmp_path, monkeypatch):
    code, out = render(tmp_path, monkeypatch)
    assert code in (0, None)
    quadlets = {p.name for p in (out / "quadlets").iterdir()}
    assert {
        "kn-proxy-se.container",
        "kn-proxy-resi.container",
        "kn-proxy-tor.container",
    } <= quadlets
    se = (out / "quadlets" / "kn-proxy-se.container").read_text()
    assert "Image=ghcr.io/derlocke-ng/kiwi-proxy/gateway:latest" in se
    assert "AddCapability=NET_ADMIN" in se and "DropCapability=ALL" in se
    assert "PublishPort=10.8.0.25:1081:1081/tcp" in se
    assert "IP=172.128.0.200" in se  # static, clear of the module address plan
    assert "Environment=KF_ENDPOINT_HOST=10.64.0.1" in se


def test_via_points_at_the_stack_module(tmp_path, monkeypatch):
    _code, out = render(tmp_path, monkeypatch)
    tor = (out / "quadlets" / "kn-proxy-tor.container").read_text()
    assert "Environment=KF_ENDPOINT_IP=172.128.0.8" in tor  # kiwi-server's tor address


def test_passwords_stay_out_of_the_units(tmp_path, monkeypatch):
    _code, out = render(tmp_path, monkeypatch)
    for unit in (out / "quadlets").iterdir():
        assert "hunter2" not in unit.read_text() and "p w" not in unit.read_text()
    table = (out / "kn-proxy" / "credentials").read_text()
    assert "resi\tu1\tp w\tme\thunter2" in table
    stack = (out / "stack.sh").read_text()
    assert "'kn-proxy/credentials:0600'" in stack
    assert "'1081-1083/tcp'" in stack


def test_an_exit_without_a_host_port_is_refused(tmp_path, monkeypatch, capsys):
    try:
        code, _ = render(tmp_path, monkeypatch, exits="      se: { host: 10.64.0.1, port: 1080 }")
    except Exception as exc:  # noqa: BLE001 - the renderer may raise or report
        assert "expose" in str(exc)
        return
    assert code
    assert "expose" in capsys.readouterr().err


def test_ad_blocking_is_fetched_through_each_exit(tmp_path, monkeypatch):
    exits = EXITS.replace("expose: 1081 }", "expose: 1081, adblock: false }")
    _code, out = render(tmp_path, monkeypatch, exits=exits)
    resi = (out / "quadlets" / "kn-proxy-resi.container").read_text()
    assert "Environment=KF_BLOCKLIST=/run/kf/blocked-names.txt" in resi
    assert "Environment=KF_BLOCKLIST_URLS=https://small.oisd.nl/domainswild2" in resi
    se = (out / "quadlets" / "kn-proxy-se.container").read_text()
    assert "KF_BLOCKLIST" not in se  # adblock: false on that exit
