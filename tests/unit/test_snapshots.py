"""Snapshots: the folder, the encryption, and which copy is newer.

Real gpg and zstd (the format is the product: a snapshot must open by hand), with
the passphrase stretching turned down so the tests stay fast. Two devices are two
sets of XDG directories pointing at one folder.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from kiwi_proxy import snapshots
from kiwi_proxy.snapshots import crypt
from kiwi_proxy.snapshots.folder import Folder

pytestmark = pytest.mark.skipif(
    bool(crypt.missing_tools()), reason="snapshots need gpg and zstd on the test machine"
)

PASS = "correct horse battery staple"
REAL_GPG_HOME = crypt._gpg_home  # before any fixture swaps it
FOLDER_MODULE = importlib.import_module("kiwi_proxy.snapshots.folder")


@pytest.fixture(scope="session")
def _gpg_home():
    """One gpg home for the whole run: a fresh one per call (what the app does)
    costs a gpg-agent start each time, which is most of a test's time."""
    home = tempfile.mkdtemp(prefix="kp-test-gpg-")
    yield home
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


@pytest.fixture(autouse=True)
def _fast_gpg(monkeypatch, _gpg_home):
    monkeypatch.setattr(crypt, "S2K_COUNT", 1024)
    monkeypatch.setattr(crypt, "_gpg_home", lambda: contextlib.nullcontext(_gpg_home))
    snapshots._session.clear()
    Folder.forget_unlocked()
    yield
    snapshots._session.clear()
    Folder.forget_unlocked()


def test_each_call_gets_its_own_gpg_home_and_leaves_nothing(monkeypatch, tmp_path):
    """What the app really does (the fixture above swaps it for speed)."""
    monkeypatch.setattr(crypt, "_gpg_home", REAL_GPG_HOME)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    crypt.encrypt_bytes(b"x", tmp_path / "x.gpg", PASS)
    assert crypt.decrypt_bytes(tmp_path / "x.gpg", PASS) == b"x"
    assert list((tmp_path / "run" / "kiwi-proxy").iterdir()) == []
    leftover = subprocess.run(["pgrep", "-f", str(tmp_path)], capture_output=True, text=True)
    assert leftover.stdout.strip() == "", "a gpg-agent outlived its call"


def device(tmp_path: Path, monkeypatch, name: str) -> None:
    """Act as another machine: its own data, config, cache and runtime dirs, and
    nothing remembered in this process."""
    for var in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(var, str(tmp_path / name / var.lower()))
    snapshots._session.clear()
    Folder.forget_unlocked()


def text_fill(text: str):
    def fill(tar):
        snapshots.add_bytes(tar, "data.txt", text.encode())

    return fill


def read_snapshot(meta, tmp_path: Path) -> str:
    out = tmp_path / f"out-{meta.id}"
    snapshots.folder().extract(meta, out)
    return (out / "data.txt").read_text()


# ------------------------------------------------------------- the folder
def test_setup_makes_a_folder_and_another_device_joins_it(tmp_path, monkeypatch):
    shared = tmp_path / "Nextcloud" / "kiwi-snapshots"
    device(tmp_path, monkeypatch, "lime")
    s, created = snapshots.setup(shared, PASS, device_name="lime")
    assert created and s.device_name == "lime" and s.keep == 5
    assert (shared / "folder.json").is_file() and (shared / "check.gpg").is_file()

    device(tmp_path, monkeypatch, "titan")
    with pytest.raises(snapshots.BadPassphrase):
        snapshots.setup(shared, "a wrong passphrase", device_name="titan")
    s2, created2 = snapshots.setup(shared, PASS, device_name="titan")
    assert not created2 and s2.device_id != s.device_id
    assert snapshots.unlocked()


def test_a_new_folder_wants_a_long_passphrase_and_an_empty_place(tmp_path, monkeypatch):
    device(tmp_path, monkeypatch, "lime")
    with pytest.raises(snapshots.SnapshotError, match="at least 12"):
        snapshots.setup(tmp_path / "f", "short")
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "photo.jpg").write_text("x")
    with pytest.raises(snapshots.SnapshotError, match="not empty"):
        snapshots.setup(busy, PASS)


def test_a_leaked_folder_says_nothing(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    snapshots.take("exit", "item-1", "mullvad-secret-name", text_fill("password=hunter2"))
    names = [str(p.relative_to(shared)) for p in shared.rglob("*")]
    assert not any("mullvad" in n or "exit" in n or "lime" in n for n in names)
    for path in shared.rglob("*.gpg"):
        blob = path.read_bytes()
        assert b"hunter2" not in blob and b"mullvad" not in blob and b"lime" not in blob


def test_a_snapshot_opens_by_hand_with_gpg_and_zstd(tmp_path, monkeypatch):
    """The promise in the docs: no kiwi app needed to get your data back."""
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS)
    meta = snapshots.take("exit", "item-1", "work", text_fill("hello"))
    snap = snapshots.folder().snap_file(meta)
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    out = tmp_path / "by-hand"
    out.mkdir()
    gpg = subprocess.run(
        [
            "gpg", "--homedir", str(home), "--batch", "--quiet", "--pinentry-mode", "loopback",
            "--passphrase", PASS, "-d", str(snap),
        ],
        capture_output=True, check=True,
    )  # fmt: skip
    plain = subprocess.run(["zstd", "-d", "-c"], input=gpg.stdout, capture_output=True, check=True)
    subprocess.run(["tar", "-x", "-C", str(out)], input=plain.stdout, check=True)
    assert (out / "data.txt").read_text() == "hello"


def test_a_damaged_or_half_synced_snapshot_is_refused(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS)
    meta = snapshots.take("exit", "item-1", "work", text_fill("hello" * 100))
    f = snapshots.folder()
    snap = f.snap_file(meta)
    data = bytearray(snap.read_bytes())
    data[len(data) // 2] ^= 0xFF
    snap.write_bytes(bytes(data))
    with pytest.raises(snapshots.SnapshotError, match="damaged"):
        f.extract(meta, tmp_path / "x")
    snap.write_bytes(bytes(data[: len(data) // 2]))
    with pytest.raises(snapshots.NotReady):
        f.extract(meta, tmp_path / "y")


def test_sync_client_leftovers_are_ignored(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS)
    meta = snapshots.take("exit", "item-1", "work", text_fill("a"))
    f = snapshots.folder()
    d = f.item_dir("exit", "item-1")
    shutil.copy(f.meta_file(meta), d / f"{meta.id} (conflicted copy 2026-11-10).meta.gpg")
    (d / f"{'0' * 16}.meta.gpg.part").write_bytes(b"half")
    assert [m.id for m in f.metas()] == [meta.id]


def test_keep_prunes_the_oldest(tmp_path, monkeypatch):
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(tmp_path / "shared", PASS)
    s = snapshots.load_settings()
    s.keep = 3
    snapshots.save_settings(s)
    taken = [snapshots.take("exit", "item-1", "work", text_fill(str(i))).id for i in range(5)]
    left = snapshots.history("exit", "item-1")
    assert [m.id for m in left] == list(reversed(taken[-3:]))
    assert len(list(snapshots.folder().item_dir("exit", "item-1").glob("*.snap.gpg"))) == 3


def test_metas_are_cached_and_read_back_on_a_new_device(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    for i in range(4):
        snapshots.take("exit", f"item-{i}", f"exit{i}", text_fill("x"))
    device(tmp_path, monkeypatch, "titan")
    snapshots.setup(shared, PASS, device_name="titan")
    cat = snapshots.catalog(("exit",))
    assert sorted(m[0].name for m in cat.values()) == ["exit0", "exit1", "exit2", "exit3"]
    assert {m[0].device for m in cat.values()} == {"lime"}
    cache = Path(os.environ["XDG_CACHE_HOME"]) / "kiwi-proxy" / "snapshot-meta"
    assert len(list(cache.rglob("*.json"))) == 4


# --------------------------------------------------------------- lineage
def test_which_copy_is_newer_follows_lineage_not_clocks(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    assert snapshots.relation("exit", "e", here=True).state == "only_here"
    a = snapshots.take("exit", "e", "work", text_fill("A"))
    assert snapshots.relation("exit", "e", here=True).state == "same"
    snapshots.mark_changed("exit", "e")
    assert snapshots.relation("exit", "e", here=True).state == "changed_here"

    device(tmp_path, monkeypatch, "titan")
    snapshots.setup(shared, PASS, device_name="titan")
    rel = snapshots.relation("exit", "e", here=False)
    assert rel.state == "not_here" and rel.head.id == a.id
    snapshots.restore("exit", "e", a.id, lambda staging, meta: None, here=False)
    assert snapshots.relation("exit", "e", here=True).state == "same"
    b = snapshots.take("exit", "e", "work", text_fill("B"))
    assert b.parent == a.id

    device(tmp_path, monkeypatch, "lime")
    rel = snapshots.relation("exit", "e", here=True)
    assert rel.state == "diverged"  # lime changed A too, and titan made B from A
    assert rel.head.id == b.id and rel.head.device == "titan"
    # "keep this device's": its snapshot wins over B, everywhere
    c = snapshots.take("exit", "e", "work", text_fill("C"), supersede=rel.heads)
    assert snapshots.relation("exit", "e", here=True).state == "same"
    assert b.id in c.ancestors

    device(tmp_path, monkeypatch, "titan")
    rel = snapshots.relation("exit", "e", here=True)
    assert rel.state == "folder_newer" and rel.head.id == c.id


def test_a_restore_keeps_what_was_here_aside(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    a = snapshots.take("exit", "e", "work", text_fill("A"))
    snapshots.mark_changed("exit", "e")
    kept = []

    def keep_current():
        kept.append(snapshots.take("exit", "e", "work", text_fill("local"), aside=True))

    seen = []
    snapshots.restore(
        "exit", "e", a.id, lambda staging, meta: seen.append((staging / "data.txt").read_text()),
        here=True, keep_current=keep_current,
    )  # fmt: skip
    assert seen == ["A"] and kept and kept[0].aside
    assert snapshots.relation("exit", "e", here=True).state == "same"  # aside is not a head
    assert read_snapshot(kept[0], tmp_path) == "local"


# ---------------------------------------------------------- the passphrase
def test_lock_forgets_and_auto_says_so(tmp_path, monkeypatch):
    device(tmp_path, monkeypatch, "lime")
    assert snapshots.auto("exit", "e", "work", text_fill("x")) is None  # not set up: silent
    snapshots.setup(tmp_path / "shared", PASS)
    assert snapshots.auto("exit", "e", "work", text_fill("x")) is None  # taken
    snapshots.lock()
    assert not snapshots.unlocked()
    note = snapshots.auto("exit", "e", "work", text_fill("y"))
    assert note and "locked" in note
    with pytest.raises(snapshots.Locked):
        snapshots.folder()
    snapshots.unlock(PASS)
    assert len(snapshots.history("exit", "e")) == 1


def test_a_passphrase_kept_here_that_no_longer_fits_reads_as_locked(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS)
    folder_id = Folder.at(shared).id
    snapshots.keyring.store(folder_id, "an old passphrase", label="x")
    snapshots._session.clear()
    Folder.forget_unlocked()
    with pytest.raises(snapshots.Locked, match="no longer opens"):
        snapshots.folder()


def test_in_use_markers_name_the_other_device(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(shared, PASS, device_name="lime")
    snapshots.mark_in_use("profile", "p1")
    assert snapshots.in_use_elsewhere("profile", "p1") == []
    device(tmp_path, monkeypatch, "titan")
    snapshots.setup(shared, PASS, device_name="titan")
    assert [d for d, _since in snapshots.in_use_elsewhere("profile", "p1")] == ["lime"]
    device(tmp_path, monkeypatch, "lime")
    snapshots.clear_in_use("profile", "p1")
    device(tmp_path, monkeypatch, "titan")
    assert snapshots.in_use_elsewhere("profile", "p1") == []


def test_when_text_reads_like_a_person():
    import datetime as dt

    now = dt.datetime(2026, 11, 10, 15, 0).astimezone()
    assert snapshots.when_text(now.replace(hour=14, minute=5), now) == "today 14:05"
    assert snapshots.when_text(now - dt.timedelta(days=1), now).startswith("yesterday")
    assert snapshots.when_text(now - dt.timedelta(days=3), now).startswith("7 November")
    assert snapshots.size_text(9 * 1024 * 1024) == "9 MB"
    assert snapshots.size_text(4500) == "4 kB"


def test_pruning_never_drops_the_newest_of_a_line(tmp_path, monkeypatch):
    """Even when another device's clock runs ahead: the copy this device stands on
    stays."""
    import datetime as dt

    device(tmp_path, monkeypatch, "lime")
    snapshots.setup(tmp_path / "shared", PASS)
    s = snapshots.load_settings()
    s.keep = 2
    snapshots.save_settings(s)
    future = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    real_now = FOLDER_MODULE._now
    monkeypatch.setattr(FOLDER_MODULE, "_now", lambda: future)  # a clock gone wrong
    snapshots.take("exit", "e", "work", text_fill("1"), aside=True)
    snapshots.take("exit", "e", "work", text_fill("2"), aside=True)
    monkeypatch.setattr(FOLDER_MODULE, "_now", real_now)
    newest = snapshots.take("exit", "e", "work", text_fill("3"))
    left = [m.id for m in snapshots.history("exit", "e")]
    assert newest.id in left and len(left) == 2
