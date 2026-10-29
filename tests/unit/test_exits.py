"""The exit store and the secret store behind it."""

from __future__ import annotations

import os

import pytest

from kiwi_proxy import exits, paths, secrets
from kiwi_proxy.models import Endpoint, Expose


def test_create_load_and_resolve():
    ex = exits.create("work", Endpoint(host="10.64.0.1", port=1080), password="pw")
    assert exits.load(ex.id) == ex
    assert exits.resolve_ref("work").id == ex.id
    assert exits.resolve_ref(ex.id[:6]).id == ex.id
    assert [e.name for e in exits.list_exits()] == ["work"]


def test_the_password_never_lands_in_json():
    ex = exits.create(
        "work", Endpoint(host="h", port=1, username="u", has_password=True), password="topsecret"
    )
    assert "topsecret" not in (paths.exit_dir(ex.id) / "exit.json").read_text()
    assert secrets.lookup(ex.id) == "topsecret"


def test_a_consumer_can_bring_its_own_id():
    # kiwi-fox registers a profile's exit under the profile id, so the gateway keeps
    # the kf-gw-<profile id> name kiwi-pentesting already knows.
    pid = "11111111-2222-3333-4444-555555555555"
    ex = exits.create("work", Endpoint(host="h", port=1), exit_id=pid, owner="kiwi-fox")
    assert ex.id == pid and ex.owner == "kiwi-fox"
    assert paths.gateway_name(ex.id) == "kf-gw-11111111-222"
    with pytest.raises(exits.ExitError, match="already exists"):
        exits.create("other", Endpoint(host="h", port=1), exit_id=pid)


def test_names_are_unique_and_sane():
    exits.create("work", Endpoint(host="h", port=1))
    with pytest.raises(exits.ExitError, match="already exists"):
        exits.create("work", Endpoint(host="h", port=2))
    for bad in ("", "a/b", "-x", "x" * 65):
        with pytest.raises(exits.ExitError):
            exits.create(bad, Endpoint(host="h", port=1))


def test_delete_clears_secrets():
    ex = exits.create(
        "work",
        Endpoint(host="h", port=1),
        password="a",
        expose=Expose(port=1081, username="me", has_password=True),
        expose_password="b",
    )
    exits.delete(ex.id)
    assert not exits.exists(ex.id)
    assert secrets.lookup(ex.id) is None
    assert secrets.lookup(ex.id, kind="expose") is None


def test_file_secrets_are_private():
    secrets.store("x", "pw")
    path = paths.secrets_dir() / "x.endpoint"
    assert path.read_text() == "pw"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_expose_address_and_loopback():
    assert Expose(port=1081).address == "127.0.0.1:1081"
    assert Expose(port=1081).loopback
    assert Expose(bind="::1", port=1).address == "[::1]:1"
    assert not Expose(bind="10.8.0.25", port=1081).loopback
