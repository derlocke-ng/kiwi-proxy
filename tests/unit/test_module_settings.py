"""Module settings: what a module needs from the user, asked the same way by the
CLI and the app; and leases by country, for modules that can filter."""

from __future__ import annotations

import pytest

from kiwi_proxy import cli, paths, providers

MODULE_SRC = """
from kiwi_proxy.models import ContainerSpec, Lease, ProviderManifest
from kiwi_proxy.providers.base import ContainerProvider, Country, ProviderError, Setting

MANIFEST = ProviderManifest(name="fakemyst", title="Fake Myst", socks_port=1080, auth="none",
                            needs_account=True, notes="bring a keystore")


class FakeMyst(ContainerProvider):
    manifest = MANIFEST

    def container_spec(self, ctx, *, lease=None, country=None):
        return ContainerSpec(name=ctx.container_name(lease), image=ctx.image, network=ctx.network)

    def settings(self, ctx):
        return [Setting("keystore", "Keystore", kind="file", help="the wallet file"),
                Setting("passphrase", "Passphrase", kind="password", required=False)]

    def configure(self, ctx, values):
        if not values.get("keystore"):
            raise ProviderError("fakemyst: the keystore file is needed")
        (ctx.state_dir / "id").write_text("0xabc")
        (ctx.state_dir / "pw").write_text(values.get("passphrase", ""))
        return ["identity 0xabc imported"]

    def configured(self, ctx):
        return "identity 0xabc" if (ctx.state_dir / "id").exists() else None

    def leases(self, ctx, *, country=None):
        all_ = [Lease(id="0xde1", country="DE", city="Berlin", kind="residential", quality=2.9, isp="Telekom"),
                Lease(id="0xse1", country="SE", city="Kista", kind="hosting", quality=3.0, isp="Bahnhof")]
        return [l for l in all_ if not country or l.country == country.upper()]

    def countries(self, ctx):
        return [Country("SE", "Sweden", 1), Country("DE", "Germany", 1)]


PROVIDER = FakeMyst()
"""


@pytest.fixture
def fakemyst():
    mdir = paths.module_dir("fakemyst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    return "fakemyst"


def _ctx(name):
    prov, manifest = providers.load(name)
    ctx = providers.context_for(name, manifest)
    ctx.state_dir.mkdir(parents=True, exist_ok=True)
    return prov, ctx


def test_settings_are_declared_and_configure_keeps_state(fakemyst):
    prov, ctx = _ctx(fakemyst)
    keys = [(s.key, s.kind, s.required) for s in prov.settings(ctx)]
    assert keys == [("keystore", "file", True), ("passphrase", "password", False)]
    assert prov.configured(ctx) is None
    assert prov.configure(ctx, {"keystore": "/x.json", "passphrase": "pw"}) == [
        "identity 0xabc imported"
    ]
    assert prov.configured(ctx) == "identity 0xabc"
    with pytest.raises(providers.ProviderError, match="keystore file is needed"):
        prov.configure(ctx, {"keystore": ""})


def test_a_module_without_settings_refuses_to_configure(fakemyst):
    from test_providers import install_module

    install_module()  # faketor
    prov, ctx = _ctx("faketor")
    assert prov.settings(ctx) == [] and prov.configured(ctx) is None
    with pytest.raises(providers.ProviderError, match="nothing to configure"):
        prov.configure(ctx, {})


def test_leases_for_filters_by_country_only_where_the_module_can(fakemyst):
    from test_providers import install_module

    prov, ctx = _ctx(fakemyst)
    assert [x.id for x in providers.leases_for(prov, ctx, "de")] == ["0xde1"]
    assert [x.id for x in providers.leases_for(prov, ctx)] == ["0xde1", "0xse1"]
    install_module()  # faketor's leases(ctx) predates the country parameter
    old, octx = _ctx("faketor")
    assert [x.id for x in providers.leases_for(old, octx, "de")] == ["de", "se"]


def test_cli_settings_config_and_leases(fakemyst, capsys):
    assert cli.main(["module", "settings", "fakemyst"]) == 0
    out = capsys.readouterr().out
    assert "keystore" in out and "[file]" in out and "not configured" in out
    assert cli.main(["module", "config", "fakemyst"]) == 1
    assert "missing: keystore" in capsys.readouterr().err
    assert cli.main(["module", "config", "fakemyst", "keystore=/w.json", "passphrase=s3"]) == 0
    assert "identity 0xabc imported" in capsys.readouterr().out
    _prov, ctx = _ctx(fakemyst)
    assert (ctx.state_dir / "pw").read_text() == "s3"
    assert cli.main(["module", "config", "fakemyst", "bogus=1"]) == 1
    assert "expected KEY=VALUE" in capsys.readouterr().err
    assert cli.main(["module", "status", "fakemyst"]) == 0
    assert "identity 0xabc" in capsys.readouterr().out
    assert cli.main(["module", "leases", "fakemyst", "--country", "se"]) == 0
    out = capsys.readouterr().out
    assert "0xse1" in out and "0xde1" not in out
    assert cli.main(["module", "leases", "fakemyst", "--country", "fr"]) == 0
    assert "no selectable leases in FR" in capsys.readouterr().out
    assert cli.main(["module", "leases", "fakemyst", "--kind", "residential"]) == 0
    out = capsys.readouterr().out
    assert "0xde1  residential  DE Berlin  Telekom" in out and "0xse1" not in out
    assert out.rstrip().endswith("1 of 2 leases")
    assert cli.main(["module", "leases", "fakemyst", "--search", "bahn"]) == 0
    out = capsys.readouterr().out
    assert "0xse1" in out and "0xde1" not in out


def test_cli_config_asks_for_a_password_unechoed(fakemyst, monkeypatch, capsys):
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "typed")
    assert (
        cli.main(["module", "config", "fakemyst", "keystore=/w.json", "--ask", "passphrase"]) == 0
    )
    _prov, ctx = _ctx(fakemyst)
    assert (ctx.state_dir / "pw").read_text() == "typed"


def test_countries_for_takes_the_modules_list_by_name(fakemyst):
    prov, ctx = _ctx(fakemyst)
    found = providers.countries_for(prov, ctx)
    assert [(c.code, c.name, c.count) for c in found] == [("DE", "Germany", 1), ("SE", "Sweden", 1)]
    assert found[0].label == "DE — Germany (1)"


def test_countries_for_offers_every_country_when_the_module_cannot_say(fakemyst):
    from test_providers import install_module

    from kiwi_proxy import countries

    install_module()  # faketor predates the countries hook
    prov, ctx = _ctx("faketor")
    found = providers.countries_for(prov, ctx)
    assert len(found) == len(countries.NAMES) > 200
    codes = [c.code for c in found]
    assert {"DE", "US", "NL"} <= set(codes)
    assert [c.name for c in found] == sorted((c.name for c in found), key=str.lower)
    assert all(c.count is None for c in found)
    assert found[[c.code for c in found].index("DE")].label == "DE — Germany"


def test_cli_countries(fakemyst, capsys):
    from test_providers import install_module

    assert cli.main(["module", "countries", "fakemyst"]) == 0
    out = capsys.readouterr().out
    assert "DE  Germany  1" in out and out.rstrip().endswith("2 countries")
    install_module()
    assert cli.main(["module", "countries", "faketor"]) == 0
    out = capsys.readouterr().out
    assert "DE  Germany\n" in out and "does not say where it can exit" in out


def test_a_module_endpoint_takes_a_country_code_only(fakemyst):
    from kiwi_proxy import exits

    assert exits.module_endpoint(fakemyst, lease=None, country="DE").country == "de"
    assert exits.module_endpoint(fakemyst, lease=None, country="").country is None
    with pytest.raises(exits.ExitError, match="two-letter code.*module countries fakemyst"):
        exits.module_endpoint(fakemyst, lease=None, country="germany")
