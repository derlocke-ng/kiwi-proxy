"""Where a Tor exit may leave: Only and Never per exit, the Eyes group for all,
a provider container per selection, and what an older kiwi-proxy still reads."""

from __future__ import annotations

import json

import pytest

from kiwi_proxy import cli, exits, gateway, paths, prefs, providers, selection
from kiwi_proxy.models import Endpoint

SELECTING = """
from kiwi_proxy.models import ContainerSpec, ProviderManifest
from kiwi_proxy.providers.base import ContainerProvider, Node

MANIFEST = ProviderManifest(
    name="tor", title="Tor", description="test", socks_port=9050, auth="isolation"
)
SEEN = []


class Tor(ContainerProvider):
    manifest = MANIFEST
    exit_selection = True

    def container_spec(self, ctx, *, lease=None, country=None, selection=None):
        SEEN.append((lease, country, selection))
        return ContainerSpec(name=ctx.container_name(lease), image=ctx.image, network=ctx.network)

    def nodes(self, ctx):
        return [
            Node("A" * 40, "fast", "SE", "Bahnhof", 90 * 1048576),
            Node("B" * 40, "us-relay", "US", "Big", 80 * 1048576),
        ]


PROVIDER = Tor()
"""
FP = "A" * 40


@pytest.fixture(autouse=True)
def tor_module():
    mdir = paths.module_dir("tor")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(SELECTING)
    selection._SUPPORTS.clear()
    yield
    selection._SUPPORTS.clear()


def tor_endpoint(**kw) -> Endpoint:
    return Endpoint(host="10.89.231.5", port=9050, module="tor", **kw)


def test_eyes_groups_are_the_published_members():
    assert set(selection.FIVE) == {"AU", "CA", "NZ", "GB", "US"}
    assert set(selection.NINE) - set(selection.FIVE) == {"DK", "FR", "NL", "NO"}
    assert set(selection.FOURTEEN) - set(selection.NINE) == {"BE", "DE", "IT", "ES", "SE"}
    assert len(selection.FOURTEEN) == 14


def test_a_selection_and_its_container():
    plain = tor_endpoint()
    assert selection.of(plain).empty and selection.lease_of(plain) is None  # the shared Tor
    a = tor_endpoint(only_countries=["de", "SE"], never_countries=["hu"])
    sel = selection.of(a)
    assert sel.only_countries == ("DE", "SE") and sel.never_countries == ("HU",)
    key = selection.lease_of(a)
    assert key.startswith("x") and key == selection.lease_of(
        tor_endpoint(only_countries=["SE", "DE"], never_countries=["HU"])
    )
    assert key != selection.lease_of(tor_endpoint(only_countries=["DE"]))
    # an exit made with --country before lists: that country only
    assert selection.of(tor_endpoint(country="nl")).only_countries == ("NL",)
    assert selection.summary(a) == "only DE, SE · never HU"


def test_the_eyes_preference_holds_for_every_tor_exit():
    prefs.save(prefs.Prefs(tor_never_group="five"))
    sel = selection.of(tor_endpoint(never_countries=["hu"]))
    assert set(sel.never_countries) == {"HU", *selection.FIVE}
    assert sel.own_never == ("HU",)
    # and moves even an exit that chose nothing to its own Tor
    assert selection.lease_of(tor_endpoint()) is not None
    bad = selection.of(tor_endpoint(only_countries=["us", "de"], never_countries=["de"]))
    problems = " ".join(bad.problems())
    assert "DE cannot be both Only and Never" in problems
    assert "US is blocked for every Tor exit" in problems


def test_a_module_without_lists_is_untouched():
    mdir = paths.module_dir("myst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(
        SELECTING.replace("    exit_selection = True\n", "").replace('name="tor"', 'name="myst"')
    )
    ep = Endpoint(host="x", port=1, module="myst", lease="0xabc", country="de")
    assert selection.of(ep) is None and selection.lease_of(ep) == "0xabc"


def test_an_exit_without_lists_is_written_as_before():
    ex = exits.create("tor-plain", tor_endpoint())
    data = json.loads((paths.exit_dir(ex.id) / "exit.json").read_text())
    assert "only_countries" not in data["endpoint"] and "never_countries" not in data["endpoint"]
    ex.endpoint.only_countries = ["DE"]
    exits.save(ex)
    data = json.loads((paths.exit_dir(ex.id) / "exit.json").read_text())
    assert data["endpoint"]["only_countries"] == ["DE"]
    assert exits.load(ex.id).endpoint.only_countries == ["DE"]


def test_the_provider_gets_the_selection_and_its_own_container(monkeypatch):
    from kiwi_proxy import podman

    monkeypatch.setattr(podman, "available", lambda: True)
    monkeypatch.setattr(podman, "network_ensure", lambda *a, **k: None)
    monkeypatch.setattr(podman, "is_running", lambda name: True)
    monkeypatch.setattr(podman, "container_ip", lambda name, net: "10.89.231.77")
    prov, manifest = providers.load("tor")  # one instance, to see what it was asked
    monkeypatch.setattr(providers, "load", lambda name: (prov, manifest))
    seen = prov.container_spec.__globals__["SEEN"]
    ex = exits.create("research", tor_endpoint(only_countries=["DE", "SE"], never_countries=["HU"]))
    plan = gateway.ensure_provider(ex)
    lease, _country, sel = seen[-1]
    assert lease == selection.lease_for(ex) and sel.only_countries == ("DE", "SE")
    assert plan.ip == "10.89.231.77"
    ex.endpoint.only_countries = ["HU"]
    with pytest.raises(gateway.GatewayError, match="cannot be both Only and Never"):
        gateway.ensure_provider(ex)


def test_cli_lists(capsys):
    assert (
        cli.main(
            [
                "add",
                "research",
                "--module",
                "tor",
                "--country",
                "de,se,ch",
                "--never",
                "hu,tr",
                "--node",
                FP,
            ]
        )
        == 0
    )
    ex = exits.find_by_name("research")
    assert ex.endpoint.only_countries == ["CH", "DE", "SE"]
    assert ex.endpoint.never_countries == ["HU", "TR"] and ex.endpoint.only_nodes == [FP]
    assert cli.main(["set", "research", "--never", ""]) == 0
    ex = exits.find_by_name("research")
    assert ex.endpoint.never_countries == [] and ex.endpoint.only_countries == ["CH", "DE", "SE"]
    assert cli.main(["set", "research", "--country", "de", "--never", "de"]) == 1
    assert "cannot be both" in capsys.readouterr().err
    assert cli.main(["add", "bad", "--module", "tor", "--country", "xx"]) == 1
    capsys.readouterr()
    assert cli.main(["module", "nodes", "tor"]) == 0
    out = capsys.readouterr().out
    assert "fast" in out and "us-relay" in out
    assert cli.main(["prefs", "--tor-never", "five"]) == 0
    assert "Five Eyes (AU, CA, NZ, GB, US)" in capsys.readouterr().out
    assert cli.main(["module", "nodes", "tor"]) == 0
    assert "us-relay" not in capsys.readouterr().out  # the group's relays are not offered


def test_a_running_exit_keeps_its_provider_until_it_restarts(monkeypatch):
    """The Eyes preference changes what an exit asks for; its running gateway
    still uses the container it was started with."""
    from kiwi_proxy import podman

    ex = exits.create("research", tor_endpoint(only_countries=["SE"]))
    started_with = selection.lease_of(ex.endpoint)
    prefs.save(prefs.Prefs(tor_never_group="five"))
    assert selection.lease_of(ex.endpoint) != started_with
    gw = paths.gateway_name(ex.id)
    running = {gw, paths.provider_container_name("tor", started_with)}
    monkeypatch.setattr(podman, "exists", lambda name: name in running)
    monkeypatch.setattr(podman, "is_running", lambda name: name in running)
    monkeypatch.setattr(
        podman, "labels", lambda name: {paths.MODULE_LABEL: "tor", paths.LEASE_LABEL: started_with}
    )
    assert gateway.provider_alive(ex) is True


def test_a_module_image_older_than_the_module_is_rebuilt_before_a_start(monkeypatch):
    import subprocess

    from kiwi_proxy import podman
    from kiwi_proxy.providers import base

    mdir = paths.module_dir("tor")
    (mdir / "containers").mkdir(parents=True, exist_ok=True)
    (mdir / "containers" / "Containerfile").write_text("FROM alpine\n")
    (mdir / "containers" / "entrypoint.sh").write_text("#!/bin/sh\necho new\n")
    prov, manifest = providers.load("tor")
    ctx = providers.context_for("tor", manifest)
    label = {"value": "<no value>"}  # built by an older kiwi-proxy: no source label
    builds = []

    def run(args, check=True, timeout=120):
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, label["value"] + "\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def build(image, cf, context, labels=None):
        builds.append(labels)
        label["value"] = labels[base.SOURCE_LABEL]

    monkeypatch.setattr(podman, "_run", run)
    monkeypatch.setattr(podman, "build", build)
    prov._ensure_current_image(ctx)
    assert len(builds) == 1 and builds[0][base.SOURCE_LABEL] == base.source_hash(
        mdir / "containers"
    )
    prov._ensure_current_image(ctx)
    assert len(builds) == 1  # current now: no second build
    (mdir / "containers" / "entrypoint.sh").write_text("#!/bin/sh\necho newer\n")
    monkeypatch.setattr(
        podman, "build", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("offline"))
    )
    with pytest.raises(providers.ProviderError, match="could not be rebuilt"):
        prov._ensure_current_image(ctx)


def test_the_group_for_every_relay_is_its_own_choice():
    prefs.save(prefs.Prefs(tor_never_group="five"))
    exit_only = selection.of(tor_endpoint())
    assert exit_only.never_anywhere == ()
    prefs.save(prefs.Prefs(tor_never_group="five", tor_never_all=True))
    everywhere = selection.of(tor_endpoint())
    assert set(everywhere.never_anywhere) == set(selection.FIVE)
    assert everywhere.key() != exit_only.key()  # a Tor of its own


def test_a_tor_browser_exit_gets_its_own_tor_and_a_control_password():
    from kiwi_proxy import secrets

    plain = exits.create("plain-tor", tor_endpoint())
    plain.socks_auth = "inject"
    tb = exits.create("tb-tor", tor_endpoint())
    tb.socks_auth = "passthrough"
    assert not selection.wants_control(plain) and selection.wants_control(tb)
    sel = selection.for_exit(tb)
    assert sel.control_for == tb.id and len(sel.control_password) > 20
    assert secrets.lookup(tb.id, kind="torcontrol") == sel.control_password
    assert selection.for_exit(tb).control_password == sel.control_password  # kept
    assert selection.lease_for(tb) != selection.lease_for(plain)  # a Tor of its own
    spec = gateway.gateway_spec(tb, "10.89.231.9", network=paths.PROVIDERS_NETWORK)
    assert spec.env["KF_CONTROL_IP"] == "10.89.231.9" and spec.env["KF_CONTROL_PORT"] == "9052"
    assert (
        "KF_CONTROL_IP"
        not in gateway.gateway_spec(plain, "10.89.231.9", network=paths.PROVIDERS_NETWORK).env
    )
