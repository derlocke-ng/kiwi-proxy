"""Exits and module settings in snapshots, and the `snapshot` commands."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from test_snapshots import PASS, _fast_gpg, _gpg_home, device  # noqa: F401 - autouse fixtures

from kiwi_proxy import cli, exits, gateway, paths, podman, secrets, snapshots
from kiwi_proxy.models import Endpoint, Expose
from kiwi_proxy.snapshots import crypt, items

pytestmark = pytest.mark.skipif(
    bool(crypt.missing_tools()), reason="snapshots need gpg and zstd on the test machine"
)


@pytest.fixture(autouse=True)
def _down(monkeypatch):
    monkeypatch.setattr(gateway, "is_up", lambda exit_id: False)


def two_devices(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    return shared


# ------------------------------------------------------------------ exits
def test_an_exit_travels_with_its_passwords(tmp_path, monkeypatch):
    shared = two_devices(tmp_path, monkeypatch)
    ex = exits.create(
        "mullvad",
        Endpoint(host="10.64.0.1", port=1080, username="me"),
        password="upstream-secret",
        expose=Expose(port=1081, username="host"),
        expose_password="host-secret",
    )
    assert items.auto_exit(ex) is None

    device(tmp_path, monkeypatch, "titan")
    snapshots.setup(shared, PASS, device_name="titan")
    assert exits.list_exits() == []
    kind, item, name = items.find_in_folder("mullvad")
    assert (kind, item, name) == ("exit", ex.id, "mullvad")
    head = snapshots.relation(kind, item, here=False).head
    restored = items.restore_exit(item, head.id)
    assert restored.name == "mullvad" and restored.endpoint.username == "me"
    assert secrets.lookup(ex.id) == "upstream-secret"
    assert secrets.lookup(ex.id, kind="expose") == "host-secret"
    assert snapshots.relation("exit", ex.id, here=True).state == "same"


def test_an_exit_is_not_restored_under_a_running_gateway_or_over_another(tmp_path, monkeypatch):
    shared = two_devices(tmp_path, monkeypatch)
    ex = exits.create("work", Endpoint(host="10.64.0.1", port=1080))
    meta = items.take_exit(ex)
    monkeypatch.setattr(gateway, "is_up", lambda exit_id: exit_id == ex.id)
    with pytest.raises(snapshots.SnapshotError, match="take it down first"):
        items.restore_exit(ex.id, meta.id)

    monkeypatch.setattr(gateway, "is_up", lambda exit_id: False)
    device(tmp_path, monkeypatch, "titan")
    snapshots.setup(shared, PASS, device_name="titan")
    exits.create("work", Endpoint(host="192.0.2.9", port=1080))  # another exit, same name
    with pytest.raises(snapshots.SnapshotError, match="already exists here"):
        items.restore_exit(ex.id, meta.id)
    assert exits.find_by_name("work").endpoint.host == "192.0.2.9"  # untouched


def test_restoring_over_a_changed_exit_keeps_it_aside(tmp_path, monkeypatch):
    two_devices(tmp_path, monkeypatch)
    ex = exits.create("work", Endpoint(host="10.64.0.1", port=1080))
    first = items.take_exit(ex)
    ex.notes = "changed here"
    exits.save(ex)
    snapshots.mark_changed("exit", ex.id)
    items.restore_exit(ex.id, first.id)
    assert exits.load(ex.id).notes == ""
    history = snapshots.history("exit", ex.id)
    aside = [m for m in history if m.aside]
    assert len(aside) == 1  # the changed copy, restorable
    items.restore_exit(ex.id, aside[0].id)
    assert exits.load(ex.id).notes == "changed here"


# ---------------------------------------------------------------- modules
class FakeSecrets:
    def __init__(self, monkeypatch):
        self.store: dict[str, str] = {}
        monkeypatch.setattr(podman, "available", lambda: True)
        monkeypatch.setattr(podman, "ps", lambda all_=True, labels=None: [])
        monkeypatch.setattr(
            podman,
            "secret_names",
            lambda prefix="": sorted(n for n in self.store if n.startswith(prefix)),
        )
        monkeypatch.setattr(podman, "secret_value", lambda n: self.store[n])
        monkeypatch.setattr(podman, "secret_set", lambda n, v: self.store.__setitem__(n, v))


def test_module_settings_travel_with_their_secret(tmp_path, monkeypatch):
    shared = two_devices(tmp_path, monkeypatch)
    fake = FakeSecrets(monkeypatch)
    state = paths.module_state_dir("mysterium")
    (state / "myst" / "keystore").mkdir(parents=True)
    (state / "myst" / "keystore" / "UTC--key").write_text('{"address": "88994e"}')
    (state / "myst" / "kf-consumer-id").write_text("0x88994e\n")
    fake.store["kf-mod-mysterium-passphrase"] = "wallet pass\n"
    assert items.auto_module("mysterium") is None

    device(tmp_path, monkeypatch, "titan")
    fake.store.clear()
    snapshots.setup(shared, PASS, device_name="titan")
    assert not items.module_has_state("mysterium")
    head = snapshots.relation("module", "mysterium", here=False).head
    items.restore_module("mysterium", head.id)
    state = paths.module_state_dir("mysterium")
    assert (state / "myst" / "kf-consumer-id").read_text() == "0x88994e\n"
    assert (state / "myst" / "keystore" / "UTC--key").is_file()
    assert fake.store == {"kf-mod-mysterium-passphrase": "wallet pass\n"}


def test_a_module_may_leave_out_what_it_rebuilds():
    patterns = ("myst/mainnet", "*.cache")
    assert items._excluded("myst/mainnet", patterns)
    assert items._excluded("myst/mainnet/db/myst.db", patterns)
    assert items._excluded("exit-countries.cache", patterns)
    assert not items._excluded("myst/keystore/UTC--x", patterns)


# -------------------------------------------------------------------- CLI
def run(monkeypatch, capsys, *argv, stdin: str | None = None):
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def test_the_cli_round_trip(tmp_path, monkeypatch, capsys):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    code, _ = run(monkeypatch, capsys, "add", "mullvad", "socks5://u:pw@10.64.0.1:1080")
    assert code == 0
    code, out = run(
        monkeypatch, capsys, "snapshot", "setup", str(shared), "--device", "lime",
        "--passphrase-stdin", stdin=PASS + "\n",
    )  # fmt: skip
    assert code == 0 and "made" in out
    code, out = run(monkeypatch, capsys, "snapshot", "now")
    assert code == 0 and "exit mullvad: snapshot taken" in out
    code, out = run(monkeypatch, capsys, "set", "mullvad", "--notes", "on lime")
    assert code == 0 and "no snapshot taken" not in out  # automatic, quietly

    device(tmp_path, monkeypatch, "titan")
    code, out = run(
        monkeypatch, capsys, "snapshot", "setup", str(shared), "--passphrase-stdin",
        stdin=PASS + "\n",
    )  # fmt: skip
    assert code == 0 and "joined" in out
    code, out = run(monkeypatch, capsys, "snapshot", "list")
    assert "mullvad" in out and "not on this device" in out
    code, out = run(monkeypatch, capsys, "snapshot", "restore", "mullvad")
    assert code == 0 and "restored exit mullvad" in out
    assert exits.find_by_name("mullvad").notes == "on lime"
    code, out = run(monkeypatch, capsys, "snapshot", "history", "mullvad")
    assert code == 0 and out.count("lime") == 2

    code, out = run(monkeypatch, capsys, "snapshot", "forget", "mullvad")
    assert code == 1 and "--yes" in out
    code, out = run(monkeypatch, capsys, "snapshot", "lock")
    code, out = run(monkeypatch, capsys, "snapshot", "list")
    assert code == 1 and "locked" in out


def test_status_before_setup(tmp_path, monkeypatch, capsys):
    device(tmp_path, monkeypatch, "lime")
    code, out = run(monkeypatch, capsys, "snapshot", "status")
    assert code == 0 and "not set up" in out


def test_settings_file_is_shared_and_strict(tmp_path, monkeypatch):
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(tmp_path / "shared", PASS, device_name="lime")
    raw = json.loads(snapshots.settings_path().read_text())
    assert set(raw) == {"folder", "device_name", "device_id", "keep", "automatic", "ask_older"}
    assert Path(raw["folder"]).is_absolute()
    assert PASS not in snapshots.settings_path().read_text()


def test_a_module_with_only_a_cache_has_nothing_to_snapshot(tmp_path, monkeypatch):
    two_devices(tmp_path, monkeypatch)
    fake = FakeSecrets(monkeypatch)
    monkeypatch.setattr(items, "_module_excludes", lambda name: ("exit-countries.json",))
    state = paths.module_state_dir("tor")
    state.mkdir(parents=True)
    (state / "exit-countries.json").write_text("{}")
    assert not items.module_has_state("tor")
    fake.store["kf-mod-tor-token"] = "t"
    assert items.module_has_state("tor")


def test_a_kept_passphrase_is_looked_up_once(tmp_path, monkeypatch):
    two_devices(tmp_path, monkeypatch)
    snapshots._session.clear()
    calls = []
    real = snapshots.keyring.lookup
    monkeypatch.setattr(snapshots.keyring, "lookup", lambda fid: calls.append(fid) or real(fid))
    for _ in range(3):
        snapshots.folder()
    assert len(calls) == 1
