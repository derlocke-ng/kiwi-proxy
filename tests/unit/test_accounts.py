"""A module with accounts (Mysterium: wallets) and its own container keys: the
key names the provider container everywhere, the account hooks are reached
through providers.*, a used account cannot be removed, and the CLI shows them."""

from __future__ import annotations

import pytest

from kiwi_proxy import cli, exits, gateway, paths, providers, selection

MODULE_SRC = """
from kiwi_proxy.models import ContainerSpec, Endpoint, ProviderManifest
from kiwi_proxy.providers.base import (Account, AccountAction, ContainerProvider, HistoryItem,
                                       ProviderError, Setting)

MANIFEST = ProviderManifest(name="fakewallets", title="Fake wallets", image="example.com/w:latest",
                            socks_port=1080, needs_account=True)
WALLETS = {"0xaa": "First", "0xbb": "Second"}
CALLS = []


class FakeWallets(ContainerProvider):
    manifest = MANIFEST
    account_noun = "wallet"
    account_option = "wallet"

    def container_spec(self, ctx, *, lease=None, country=None):
        return ContainerSpec(name=ctx.container_name(lease), image=ctx.image, network=ctx.network)

    def exit_options(self, ctx):
        return [Setting("wallet", "Wallet", kind="choice", required=False)]

    def lease_key(self, ctx, *, lease=None, country=None, options=None):
        return f"w{self.account_of(ctx, options)[2:]}-{lease or country or 'any'}"

    def up(self, ctx, *, lease=None, country=None, options=None):
        CALLS.append(("up", lease, dict(options or {})))
        return Endpoint(host="10.89.0.9", port=1080, module="fakewallets", lease=lease)

    def account_of(self, ctx, options):
        return (options or {}).get("wallet") or "0xaa"

    def accounts(self, ctx, *, refresh=False, only=None):
        CALLS.append(("accounts", refresh, only))
        return [Account(id=i, name=n, state="1.0 MYST", address="0xchan" + i[2:],
                        address_note="Top-up address", actions=(AccountAction("register", "Register now"),))
                for i, n in WALLETS.items() if not only or only == i]

    def account_new_settings(self, ctx):
        return [Setting("name", "Name", required=False)]

    def account_new(self, ctx, values):
        WALLETS["0xcc"] = values.get("name") or "Third"
        return ["wallet made"]

    def account_history(self, ctx, account):
        return [HistoryItem("2026-11-20 06:00", "Session · DE", "-0.0020 MYST", "10 min")]

    def account_act(self, ctx, account, action):
        return [f"{action} {account}"]

    def account_rename(self, ctx, account, name):
        WALLETS[account] = name

    def account_export(self, ctx, account, dest):
        return dest + "/" + account + ".json"

    def account_remove(self, ctx, account):
        WALLETS.pop(account)
        return [f"{account} removed"]


PROVIDER = FakeWallets()
"""


@pytest.fixture
def wallets_module():
    mdir = paths.module_dir("fakewallets")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    return "fakewallets"


def _exit(name, module, wallet=None, country="de"):
    ex = exits.create(name, exits.module_endpoint(module, lease=None, country=country))
    if wallet:
        ex.endpoint.options = {"wallet": wallet}
        exits.save(ex)
    return exits.load(ex.id)


def test_the_modules_key_names_the_provider_container(wallets_module):
    a = _exit("a", wallets_module)
    b = _exit("b", wallets_module, wallet="0xbb")
    assert providers.keys_leases(wallets_module)
    assert selection.lease_for(a) == "waa-de"
    assert selection.lease_for(b) == "wbb-de"
    assert selection.lease_of(b.endpoint) == "wbb-de"
    assert gateway._provider_lease(b) == "wbb-de"
    assert providers.container_of(wallets_module, "wbb-de") == paths.provider_container_name(
        wallets_module, "wbb-de"
    )


def test_up_is_handed_the_key_and_the_options(wallets_module):
    b = _exit("b", wallets_module, wallet="0xbb")
    prov, manifest = providers.load(wallets_module)
    ctx = providers.context_for(wallets_module, manifest)
    gateway._provider_up(prov, ctx, b)
    assert prov.up.__globals__["CALLS"][-1] == ("up", "wbb-de", {"wallet": "0xbb"})


def test_accounts_through_providers(wallets_module):
    assert providers.has_accounts(wallets_module)
    assert providers.account_noun(wallets_module) == "wallet"
    found = providers.accounts(wallets_module, refresh=True, only="0xbb")
    assert [(x.id, x.name) for x in found] == [("0xbb", "Second")]
    assert providers.account_history(wallets_module, "0xaa")[0].amount == "-0.0020 MYST"
    assert providers.account_act(wallets_module, "0xaa", "register") == ["register 0xaa"]
    assert providers.account_export(wallets_module, "0xaa", "/tmp/x") == "/tmp/x/0xaa.json"
    assert not providers.has_accounts("tor")


def test_a_used_account_is_not_removed(wallets_module):
    _exit("a", wallets_module)  # the default wallet, 0xaa
    _exit("b", wallets_module, wallet="0xbb")
    assert providers.account_users(wallets_module, "0xaa") == ["a"]
    with pytest.raises(providers.ProviderError, match="used by b"):
        providers.account_remove(wallets_module, "0xbb")
    exits.delete(exits.find_by_name("b").id)
    assert providers.account_remove(wallets_module, "0xbb") == ["0xbb removed"]


def test_cli_lists_shows_and_acts(wallets_module, capsys):
    _exit("a", wallets_module)
    assert cli.main(["module", "accounts", wallets_module]) == 0
    out = capsys.readouterr().out
    assert "0xaa  First  1.0 MYST · used by a" in out and "0xbb  Second" in out
    assert cli.main(["module", "account", wallets_module, "show", "Second"]) == 0
    out = capsys.readouterr().out
    assert "address 0xchanbb  (Top-up address)" in out
    assert "2026-11-20 06:00  Session · DE  -0.0020 MYST  10 min" in out
    assert cli.main(["module", "account", wallets_module, "do", "0xbb", "register"]) == 0
    assert "register 0xbb" in capsys.readouterr().out
    assert cli.main(["module", "account", wallets_module, "do", "0xbb", "fly"]) == 1
    assert cli.main(["module", "account", wallets_module, "new", "name=Third"]) == 0
    assert "wallet made" in capsys.readouterr().out
    assert cli.main(["module", "account", wallets_module, "rename", "0xbb", "Spare"]) == 0
    assert cli.main(["module", "account", wallets_module, "show", "nope"]) == 1


def test_a_wallet_given_by_name_is_kept_by_its_id(wallets_module, capsys):
    assert providers.clean_options(wallets_module, {"wallet": "Second"}) == {"wallet": "0xbb"}
    assert providers.clean_options(wallets_module, {"wallet": "bb"}) == {"wallet": "0xbb"}
    with pytest.raises(
        providers.ProviderError, match="no wallet 'Third' \\(there are: First, Second\\)"
    ):
        providers.clean_options(wallets_module, {"wallet": "Third"})
    assert (
        cli.main(
            ["add", "b", "--module", wallets_module, "--country", "de", "--opt", "wallet=Second"]
        )
        == 0
    )
    assert exits.find_by_name("b").endpoint.options == {"wallet": "0xbb"}
    capsys.readouterr()
    assert cli.main(["show", "b"]) == 0
    assert "  wallet    Second" in capsys.readouterr().out
    assert providers.account_label(wallets_module, {}) == "First"
