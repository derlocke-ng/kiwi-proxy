"""A module whose leases are handed out and served by one container (9proxy:
ports 60000-60009 on one daemon), with a new IP only on request (renew)."""

from __future__ import annotations

import pytest

from kiwi_proxy import cli, exits, gateway, paths, podman, providers

MODULE_SRC = """
from kiwi_proxy.models import ContainerSpec, ProviderManifest
from kiwi_proxy.providers.base import ContainerProvider, ProviderError

MANIFEST = ProviderManifest(name="fakeports", title="Fake ports", image="example.com/p:latest",
                            socks_port=60000, needs_account=True)
PORTS = [str(60000 + i) for i in range(3)]


class FakePorts(ContainerProvider):
    manifest = MANIFEST
    lease_noun = "port"

    def container_spec(self, ctx, *, lease=None, country=None):
        return ContainerSpec(name=ctx.container_name(), image=ctx.image, network=ctx.network)

    def container_for(self, ctx, lease=None):
        return ctx.container_name()

    def assign_lease(self, ctx, taken):
        for p in PORTS:
            if p not in taken:
                return p
        raise ProviderError("all three ports are taken")

    def alive(self, ctx, lease=None):
        return lease == "60000"

    def renew(self, ctx, *, lease=None, country=None):
        return [f"a new IP on port {lease}", f"country {country}"]


PROVIDER = FakePorts()
"""


@pytest.fixture
def ports_module():
    mdir = paths.module_dir("fakeports")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    return "fakeports"


def _new(name, module, country=None):
    return exits.create(name, exits.module_endpoint(module, lease=None, country=country))


def test_each_new_exit_gets_the_next_free_port(ports_module):
    a, b, c = (_new(n, ports_module) for n in ("a", "b", "c"))
    assert [e.endpoint.lease for e in (a, b, c)] == ["60000", "60001", "60002"]
    assert b.endpoint.port == 60001  # the label says which port
    with pytest.raises(providers.ProviderError, match="all three ports"):
        _new("d", ports_module)
    exits.delete(b.id)
    assert _new("e", ports_module).endpoint.lease == "60001"  # freed, given again


def test_one_container_serves_every_lease(ports_module):
    shared = paths.provider_container_name(ports_module, None)
    assert providers.container_of(ports_module, "60001") == shared
    assert providers.lease_alive(ports_module, "60000") is True
    assert providers.lease_alive(ports_module, "60001") is False


def test_a_new_ip_only_on_request(ports_module, monkeypatch, capsys):
    monkeypatch.setattr(podman, "is_running", lambda name: False)
    ex = _new("work", ports_module, country="us")
    assert gateway.renews(ex)
    lines, info = gateway.renew(ex)
    assert lines == ["a new IP on port 60000", "country us"] and info is None
    assert cli.main(["renew", "work"]) == 0
    out = capsys.readouterr().out
    assert "uses one from your balance" in out and "a new IP on port 60000" in out


def test_other_exits_have_no_new_ip(new_exit, capsys):
    ex = new_exit()
    exits.save(ex)
    assert not gateway.renews(ex)
    assert cli.main(["renew", ex.name]) == 1
    assert "no new IPs" in capsys.readouterr().err
