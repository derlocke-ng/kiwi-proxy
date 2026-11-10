"""Snapshots: encrypted copies of what the kiwi apps hold, in one folder that syncs.

One folder, chosen once per device, is shared by Kiwi Proxy (exits, module
settings), Kiwi Fox (profiles) and Kiwi Custodia (boxes). The apps never sync
anything themselves: the user adds the folder to a sync client (Nextcloud) and the
apps only ever write finished, encrypted, never-changing files into it (see
``folder``). This module is the part every app shares: settings, the passphrase,
taking and restoring a snapshot, and how this device's copy of an item relates to
the folder's.

**Which copy is newer** is decided by lineage, never by clocks: every snapshot
names its parent (the snapshot the device's copy came from) and that one's
ancestors, and every device remembers, per item, the snapshot its copy came from
(its *base*) and whether it changed since. Two machines' clocks never matter.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import io
import json
import shutil
import socket
import tarfile
import tempfile
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field

from .. import __version__, paths
from . import crypt, keyring
from .errors import BadPassphrase, Locked, NotReady, NotSetUp, SnapshotError
from .folder import ANCESTORS, Folder, Meta
from .folder import heads as _line_heads

__all__ = [
    "BadPassphrase",
    "Folder",
    "Locked",
    "Meta",
    "NotReady",
    "NotSetUp",
    "Relation",
    "Settings",
    "SnapshotError",
]

KINDS = ("exit", "module", "profile", "box")
MIN_PASSPHRASE = 12
MAX_KEEP = 10
SETTINGS_FILE = "snapshots.json"

# A passphrase entered in this process when the keyring could not keep it.
_session: dict[str, str] = {}


# ------------------------------------------------------------------- settings
class Settings(BaseModel):
    """This device's snapshot settings, one file for all three apps."""

    folder: str
    device_name: str
    device_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    keep: int = Field(5, ge=1, le=MAX_KEEP)
    automatic: bool = True
    ask_older: bool = True


def settings_path() -> Path:
    return paths.config_dir() / SETTINGS_FILE


def load_settings() -> Settings | None:
    path = settings_path()
    if not path.is_file():
        return None
    try:
        return Settings.model_validate_json(path.read_text())
    except ValueError:
        return None


def save_settings(s: Settings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(s.model_dump_json(indent=2) + "\n")
    tmp.replace(path)


def missing_tools() -> list[str]:
    return crypt.missing_tools()


# ---------------------------------------------------------------- the folder
def setup(
    folder: Path, passphrase: str, *, device_name: str | None = None, remember: bool = True
) -> tuple[Settings, bool]:
    """Use `folder` on this device: join it when it is a snapshot folder already
    (the passphrase must fit), make it one otherwise. Returns (settings, created)."""
    if missing := missing_tools():
        raise SnapshotError(f"snapshots need {' and '.join(missing)}, which this machine lacks")
    folder = folder.expanduser().absolute()
    existing = Folder.at(folder)
    if existing is not None:
        existing.unlock(passphrase)
        opened, created = existing, False
    else:
        if len(passphrase) < MIN_PASSPHRASE:
            raise SnapshotError(f"choose a passphrase of at least {MIN_PASSPHRASE} characters")
        opened, created = Folder.create(folder, passphrase), True
    old = load_settings()
    s = Settings(
        folder=str(folder),
        device_name=device_name or (old.device_name if old else socket.gethostname()),
        device_id=old.device_id if old else str(uuid.uuid4()),
        keep=old.keep if old else 5,
        automatic=old.automatic if old else True,
        ask_older=old.ask_older if old else True,
    )
    save_settings(s)
    _remember(opened.id, passphrase, remember)
    return s, created


def _remember(folder_id: str, passphrase: str, remember: bool) -> None:
    _session[folder_id] = passphrase
    if remember:
        keyring.store(folder_id, passphrase, label=f"Kiwi snapshots ({folder_id[:8]})")


def _settings() -> Settings:
    s = load_settings()
    if s is None:
        raise NotSetUp("no snapshot folder is set up on this device")
    return s


def folder(passphrase: str | None = None) -> Folder:
    """This device's snapshot folder, unlocked. Raises NotSetUp, Locked, or
    SnapshotError when the folder is not there."""
    s = _settings()
    opened = Folder.at(Path(s.folder))
    if opened is None:
        raise SnapshotError(f"{s.folder} is not there, or not synced yet")
    given = passphrase or _session.get(opened.id)
    kept = None if given else keyring.lookup(opened.id)
    secret = given or kept
    if not secret:
        raise Locked("snapshots are locked on this device; unlock them with the passphrase")
    try:
        opened.unlock(secret)
    except BadPassphrase as exc:
        if kept:
            raise Locked(
                "the passphrase kept on this device no longer opens the folder; unlock again"
            ) from exc
        raise
    if kept:
        # Asked once per process: a window polls, and a keyring that happens to be
        # locked must not prompt every few seconds.
        _session[opened.id] = kept
    return opened


def unlock(passphrase: str, *, remember: bool = True) -> Folder:
    opened = folder(passphrase)
    _remember(opened.id, passphrase, remember)
    return opened


def lock() -> None:
    """Forget the passphrase on this device (keyring and this process)."""
    s = load_settings()
    if s is None:
        return
    opened = Folder.at(Path(s.folder))
    folder_id = opened.id if opened else None
    if folder_id:
        keyring.clear(folder_id)
        _session.pop(folder_id, None)
        Folder.forget_unlocked(folder_id)


def unlocked() -> bool:
    """Set up and the passphrase at hand, without checking it against the folder."""
    s = load_settings()
    if s is None:
        return False
    opened = Folder.at(Path(s.folder))
    return bool(opened and (_session.get(opened.id) or keyring.lookup(opened.id)))


@dataclass
class Status:
    settings: Settings | None
    folder_present: bool
    unlocked: bool
    missing_tools: list[str]


def status() -> Status:
    s = load_settings()
    present = bool(s and Folder.at(Path(s.folder)))
    return Status(s, present, unlocked() if present else False, missing_tools())


# ---------------------------------------------------------- per-item state
@dataclass
class ItemState:
    """This device's copy of an item: the snapshot it came from, and whether it
    changed since."""

    base: str | None = None
    ancestors: list[str] = field(default_factory=list)
    changed: bool = False


def _state_file(folder_id: str, kind: str, item: str) -> Path:
    return paths.data_dir() / "snapshot-state" / folder_id / kind / f"{item}.json"


def _load_state(folder_id: str, kind: str, item: str) -> ItemState:
    try:
        d = json.loads(_state_file(folder_id, kind, item).read_text())
        return ItemState(d.get("base"), list(d.get("ancestors") or []), bool(d.get("changed")))
    except (OSError, ValueError):
        return ItemState()


def _save_state(folder_id: str, kind: str, item: str, st: ItemState) -> None:
    path = _state_file(folder_id, kind, item)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"base": st.base, "ancestors": st.ancestors, "changed": st.changed}))
    tmp.replace(path)


@contextlib.contextmanager
def _item_lock(kind: str, item: str) -> Iterator[None]:
    """One snapshot or restore of an item at a time, across the three apps."""
    directory = paths.runtime_dir() / "snapshot-locks"
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / f"{kind}-{item}.lock").open("w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def base_of(kind: str, item: str, folder_id: str) -> str | None:
    """The snapshot this device's copy of an item came from, if any."""
    return _load_state(folder_id, kind, item).base


def mark_changed(kind: str, item: str) -> None:
    """This device's copy changed (a profile ran, a box was used). No-op when
    snapshots are not set up."""
    s = load_settings()
    opened = Folder.at(Path(s.folder)) if s else None
    if opened is None:
        return
    st = _load_state(opened.id, kind, item)
    if not st.changed:
        st.changed = True
        _save_state(opened.id, kind, item, st)


def forget_local(kind: str, item: str) -> None:
    """The item is gone from this device: forget what its copy came from."""
    s = load_settings()
    opened = Folder.at(Path(s.folder)) if s else None
    if opened is not None:
        _state_file(opened.id, kind, item).unlink(missing_ok=True)


# ------------------------------------------------------------------ take
def add_bytes(tar: tarfile.TarFile, name: str, data: bytes, *, mode: int = 0o600) -> None:
    """Put `data` into the archive as the file `name`."""
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(dt.datetime.now(dt.UTC).timestamp())
    tar.addfile(info, io.BytesIO(data))


def take(
    kind: str,
    item: str,
    name: str,
    fill: Callable[[tarfile.TarFile], None],
    *,
    extra: dict | None = None,
    aside: bool = False,
    supersede: list[Meta] | None = None,
    app: str = "kiwi-proxy",
    version: str = __version__,
) -> Meta:
    """Snapshot this device's copy of an item into the folder, then prune the
    item to the number to keep. `aside` keeps it without making it the copy's new
    base (the copy is about to be replaced by a restore). `supersede` lists
    snapshots from other devices this copy wins over (the user chose it)."""
    if kind not in KINDS:
        raise SnapshotError(f"unknown kind {kind!r}")
    s = _settings()
    opened = folder()
    with _item_lock(kind, item):
        st = _load_state(opened.id, kind, item)
        line = [st.base, *st.ancestors] if st.base else []
        # "Keep this device's": the snapshots it wins over become its ancestors, so
        # the other devices see a newer copy instead of two lines.
        for other in supersede or ():
            line += [other.id, *other.ancestors]
        ancestors = list(dict.fromkeys(a for a in line if a))[:ANCESTORS]
        meta = opened.write(
            kind=kind,
            item=item,
            name=name,
            device=s.device_name,
            device_id=s.device_id,
            parent=st.base,
            ancestors=ancestors,
            app=app,
            version=version,
            fill=fill,
            extra=extra,
            aside=aside,
        )
        if not aside:
            _save_state(opened.id, kind, item, ItemState(meta.id, ancestors, False))
        opened.prune(kind, item, s.keep)
    return meta


def auto(
    kind: str,
    item: str,
    name: str,
    fill: Callable[[tarfile.TarFile], None],
    *,
    extra: dict | None = None,
    app: str = "kiwi-proxy",
    version: str = __version__,
) -> str | None:
    """An automatic snapshot: nothing when snapshots are not set up or switched
    off; otherwise taken, and a line to show when that was not possible. Never
    raises — it rides along with something else the user did."""
    s = load_settings()
    if s is None or not s.automatic:
        return None
    try:
        take(kind, item, name, fill, extra=extra, app=app, version=version)
    except Locked:
        return "no snapshot taken: snapshots are locked on this device"
    except (SnapshotError, OSError) as exc:
        return f"no snapshot taken: {exc}"
    return None


# --------------------------------------------------------------- reading
def history(kind: str, item: str) -> list[Meta]:
    return folder().metas(kind, item)


def catalog(kinds: tuple[str, ...] = KINDS) -> dict[tuple[str, str], list[Meta]]:
    """Every item in the folder of the given kinds, with its snapshots newest
    first."""
    out: dict[tuple[str, str], list[Meta]] = {}
    for meta in folder().metas():
        if meta.kind in kinds:
            out.setdefault((meta.kind, meta.item), []).append(meta)
    return out


@dataclass
class Relation:
    """How this device's copy of an item relates to the folder's snapshots.

    state:
      none          no snapshot, and not on this device
      only_here     on this device, never snapshotted
      not_here      snapshots exist, the item is not on this device
      same          this device's copy is the newest snapshot
      changed_here  this device's copy is newer (changed since its snapshot)
      folder_newer  the folder holds a newer snapshot than this device's copy
      diverged      both changed since they parted; someone has to choose
    """

    state: str
    head: Meta | None = None
    heads: list[Meta] = field(default_factory=list)

    @property
    def newer_elsewhere(self) -> bool:
        return self.state in ("folder_newer", "diverged")

    def describe(self) -> str:
        h = self.head
        when = f"{h.device}, {when_text(h.created)}" if h else ""
        return {
            "none": "no snapshot",
            "only_here": "no snapshot yet",
            "not_here": f"not on this device · newest from {when}",
            "same": f"snapshot {when_text(h.created)}" if h else "snapshot taken",
            "changed_here": "changed since its last snapshot",
            "folder_newer": f"newer snapshot from {when}",
            "diverged": f"changed here and on {h.device}" if h else "changed on two devices",
        }[self.state]


def relation(
    kind: str,
    item: str,
    *,
    here: bool,
    metas: list[Meta] | None = None,
    folder_id: str | None = None,
) -> Relation:
    """Compare this device's copy with the folder. `metas` (newest first) and
    `folder_id` save a folder read when the caller has them."""
    if metas is None or folder_id is None:
        opened = folder()
        metas, folder_id = opened.metas(kind, item), opened.id
    heads = _line_heads(metas)
    head = heads[0] if heads else (metas[0] if metas else None)
    if not metas:
        return Relation("only_here" if here else "none")
    if not here:
        return Relation("not_here", head, heads)
    st = _load_state(folder_id, kind, item)
    if st.base is None:
        return Relation("diverged", head, heads)  # a copy of unknown origin
    if len(heads) > 1 and any(st.base != h.id and st.base not in h.ancestors for h in heads):
        return Relation("diverged", heads[0], heads)
    assert head is not None
    if head.id == st.base:
        return Relation("changed_here" if st.changed else "same", head, heads)
    if st.base in head.ancestors:
        return Relation("diverged" if st.changed else "folder_newer", head, heads)
    if head.id in st.ancestors:
        return Relation("changed_here", head, heads)  # ours is newer, the folder lost it
    return Relation("diverged", head, heads)


# --------------------------------------------------------------- restore
def restore(
    kind: str,
    item: str,
    sid: str,
    apply: Callable[[Path, Meta], None],
    *,
    here: bool,
    keep_current: Callable[[], object] | None = None,
    staging_root: Path | None = None,
) -> Meta:
    """Restore one snapshot: unpack it into a staging folder, hand that to `apply`
    (which moves it into place), and record it as this device's base.

    When the device has a copy with unsnapshotted changes, `keep_current` is called
    first; it takes a snapshot *aside*, so the restore can be undone."""
    opened = folder()
    metas = opened.metas(kind, item)
    meta = next((m for m in metas if m.id == sid or m.id.startswith(sid)), None)
    if meta is None:
        raise SnapshotError(f"no snapshot {sid} of this item in the folder")
    if not opened.ready(meta):
        raise NotReady(
            f"the snapshot of {meta.name} from {meta.device} has not fully arrived yet; "
            "wait for the sync to finish"
        )
    if here and keep_current is not None:
        st = _load_state(opened.id, kind, item)
        if st.changed or st.base is None or st.base != meta.id:
            keep_current()
    root = staging_root or paths.data_dir()
    root.mkdir(parents=True, exist_ok=True)
    with _item_lock(kind, item):
        staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=root))
        try:
            opened.extract(meta, staging)
            apply(staging, meta)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        _save_state(opened.id, kind, item, ItemState(meta.id, list(meta.ancestors), False))
    return meta


def forget(kind: str, item: str) -> int:
    """Delete every snapshot of an item from the folder."""
    opened = folder()
    removed = opened.forget(kind, item)
    _state_file(opened.id, kind, item).unlink(missing_ok=True)
    return removed


# ---------------------------------------------------------------- in use
def mark_in_use(kind: str, item: str) -> None:
    s = _settings()
    folder().mark_in_use(kind, item, s.device_id, s.device_name)


def clear_in_use(kind: str, item: str) -> None:
    s = _settings()
    folder().clear_in_use(kind, item, s.device_id)


def in_use_elsewhere(kind: str, item: str) -> list[tuple[str, dt.datetime]]:
    s = _settings()
    return folder().in_use_elsewhere(kind, item, s.device_id)


# ---------------------------------------------------------------- wording
def when_text(moment: dt.datetime, now: dt.datetime | None = None) -> str:
    """ "today 14:05", "yesterday 22:10", "8 November 18:40", in local time."""
    local = moment.astimezone()
    today = (now or dt.datetime.now().astimezone()).date()
    clock = local.strftime("%H:%M")
    if local.date() == today:
        return f"today {clock}"
    if local.date() == today - dt.timedelta(days=1):
        return f"yesterday {clock}"
    day = f"{local.day} {local.strftime('%B')}"
    if local.year != today.year:
        day += f" {local.year}"
    return f"{day} {clock}"


def size_text(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size // 1024} kB"
    return f"{size / (1024 * 1024):.1f} MB".replace(".0 MB", " MB")
