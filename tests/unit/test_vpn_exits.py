"""A VPN exit: a tunnel module (joins="tunnel") with one config per exit,
added with `kiwi-proxy add NAME --module M --config FILE`."""

from __future__ import annotations

import pytest

from kiwi_proxy import cli, exits, paths, providers, secrets

MODULE_SRC = """
from kiwi_proxy.models import ContainerSpec, ProviderManifest
from kiwi_proxy.providers.base import ProviderError, TunnelProvider

MANIFEST = ProviderManifest(name="fakevpn", title="Fake VPN", image="example.com/g:latest",
                            needs_account=True, joins="tunnel")


class FakeVpn(TunnelProvider):
    manifest = MANIFEST

    def config_server(self, text):
        return ("vpn.example.org", 51820)

    def check_config(self, text):
        if "0.0.0.0/0" not in text:
            raise ProviderError("this config only reaches a subnet; a VPN exit needs a full tunnel")
        return "WireGuard · vpn.example.org:51820"

    def tunnel_spec(self, ctx, *, lease=None, country=None):
        return ContainerSpec(name=ctx.container_name(lease), image=ctx.image, network=ctx.network)


PROVIDER = FakeVpn()
"""

FULL = "[Interface]\nPrivateKey = x\n[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.org:51820\n"


@pytest.fixture
def vpn_module(monkeypatch):
    monkeypatch.setenv("KIWI_PROXY_SECRETS", "file")
    mdir = paths.module_dir("fakevpn")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    return "fakevpn"


def test_add_keeps_the_config_as_the_exits_secret(vpn_module, tmp_path, capsys):
    conf = tmp_path / "wg0.conf"
    conf.write_text(FULL)
    assert cli.main(["add", "v1", "--module", vpn_module, "--config", str(conf)]) == 0
    ex = exits.find_by_name("v1")
    assert ex.endpoint.lease == ex.id  # a tunnel of its own
    assert ex.endpoint.label == "fakevpn:vpn.example.org:51820"  # its server, not a bridge address
    assert secrets.lookup(ex.id, kind="vpnconfig") == FULL
    assert ex.dns.mode == "resolver"
    assert "WireGuard · vpn.example.org:51820" in capsys.readouterr().out
    assert providers.takes_config(vpn_module)


def test_a_config_that_is_not_a_full_tunnel_is_refused_before_anything_is_made(
    vpn_module, tmp_path, capsys
):
    conf = tmp_path / "split.conf"
    conf.write_text(FULL.replace("0.0.0.0/0", "10.8.0.1/24"))
    assert cli.main(["add", "v2", "--module", vpn_module, "--config", str(conf)]) == 1
    assert "full tunnel" in capsys.readouterr().err
    assert exits.find_by_name("v2") is None


def test_a_vpn_exit_needs_its_config(vpn_module, capsys):
    assert cli.main(["add", "v3", "--module", vpn_module]) == 1
    assert "--config FILE" in capsys.readouterr().err


def test_a_vpn_exit_resolves_names_itself(vpn_module, tmp_path, capsys):
    conf = tmp_path / "wg0.conf"
    conf.write_text(FULL)
    args = ["add", "v4", "--module", vpn_module, "--config", str(conf), "--dns", "remote"]
    assert cli.main(args) == 1
    assert "resolves names itself" in capsys.readouterr().err


def test_deleting_the_exit_forgets_its_config(vpn_module, tmp_path):
    conf = tmp_path / "wg0.conf"
    conf.write_text(FULL)
    cli.main(["add", "v5", "--module", vpn_module, "--config", str(conf)])
    ex = exits.find_by_name("v5")
    exits.delete(ex.id)
    assert secrets.lookup(ex.id, kind="vpnconfig") is None


def test_a_line_says_only_what_the_label_does_not(new_exit):
    from kiwi_proxy.models import Endpoint

    vpn = exits.create("v", Endpoint(host="94.16.108.143", port=51820, module="vpn"))
    vpn.endpoint.lease = vpn.id  # its own tunnel: nothing to add
    assert exits.where(vpn) == "vpn:94.16.108.143:51820"
    np = exits.create(
        "n", Endpoint(host="10.89.231.23", port=60001, module="9proxy", lease="60001", country="de")
    )
    assert exits.where(np) == "9proxy:10.89.231.23:60001 (DE)"
    myst = exits.create(
        "m", Endpoint(host="10.89.231.9", port=1080, module="mysterium", lease="0xabc")
    )
    assert exits.where(myst) == "mysterium:10.89.231.9:1080 (0xabc)"
