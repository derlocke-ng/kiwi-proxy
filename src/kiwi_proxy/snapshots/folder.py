"""The snapshot folder: its layout, and how files get into it and out of it.

::

    <folder>/
      folder.json                   {"format": 1, "kind": "kiwi-snapshots", "id": …}
      check.gpg                     encrypted {"id": …, "salt": …}: proves a passphrase
      items/<key>/<sid>.meta.gpg    what the snapshot is (name, device, time, parent…)
      items/<key>/<sid>.snap.gpg    the data: tar, zstd, gpg
      items/<key>/inuse-<device id>.gpg   "in use on lime since 14:00"

Nothing in a name says what it is: ``<key>`` is an HMAC of kind and item id under a
secret salt that only ``check.gpg`` holds, and ``<sid>`` is random. Kinds, names,
devices and times are inside the encrypted meta.

Files are written under a ``.part`` name and renamed when complete (the Nextcloud
client ignores ``*.part``), the data before its meta, so a meta in the folder means
the snapshot is complete on the device that made it. Files are never changed after
that: a new snapshot is a new pair, an old one is deleted. Sync clients then have
nothing to merge and nothing to make conflict copies of.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import tarfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import paths
from . import crypt
from .errors import NotReady, SnapshotError

FORMAT = 1
MARK = "kiwi-snapshots"
FOLDER_FILE = "folder.json"
CHECK_FILE = "check.gpg"
ITEMS = "items"
_SID = re.compile(r"^[0-9a-f]{16}$")
_META = ".meta.gpg"
_SNAP = ".snap.gpg"
_INUSE = "inuse-"


def _now() -> dt.datetime:
    # Microseconds: two snapshots of an item can come within one second (the copy
    # kept aside before a restore, then the next change).
    return dt.datetime.now(dt.UTC)


def heads(metas: list[Meta]) -> list[Meta]:
    """The newest snapshot of each line: not an ancestor of any other, and not one
    kept aside before a restore. `metas` newest first; so is the result."""
    lines = [m for m in metas if not m.aside]
    parents = {a for m in lines for a in m.ancestors}
    return [m for m in lines if m.id not in parents]


def _replace_from_part(part: Path, final: Path) -> None:
    os.replace(part, final)


@dataclass
class Meta:
    """One snapshot, as its encrypted meta file describes it."""

    id: str
    kind: str
    item: str
    name: str
    device: str
    device_id: str
    created: dt.datetime
    parent: str | None
    ancestors: list[str]  # parent first, then its parent…, at most ANCESTORS long
    size: int
    sha256: str
    app: str
    version: str
    extra: dict = field(default_factory=dict)
    aside: bool = False  # kept before a restore replaced it; never the line's head
    format: int = FORMAT

    def to_json(self) -> bytes:
        d = asdict(self)
        d["created"] = self.created.isoformat()
        return json.dumps(d, sort_keys=True).encode()

    @classmethod
    def from_json(cls, data: bytes | str) -> Meta:
        d = json.loads(data)
        d["created"] = dt.datetime.fromisoformat(d["created"])
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


ANCESTORS = 50


def _digest(path: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(crypt.CHUNK):
            size += len(chunk)
            h.update(chunk)
    return size, h.hexdigest()


class Folder:
    """A snapshot folder. Open with :meth:`at` or :meth:`create`; nothing in it can
    be read or written before :meth:`unlock`."""

    # Verified passphrases and salts in this process, per folder id: unlocking costs
    # a gpg call, and a window asks every few seconds.
    _unlocked: dict[str, tuple[str, str]] = {}

    def __init__(self, path: Path, folder_id: str) -> None:
        self.path = path
        self.id = folder_id
        self._passphrase: str | None = None
        self._salt: bytes | None = None
        self.unreadable: list[Path] = []

    # ----------------------------------------------------------------- open
    @classmethod
    def at(cls, path: Path) -> Folder | None:
        """The snapshot folder at `path`, or None when there is none (yet)."""
        marker = path / FOLDER_FILE
        if not marker.is_file():
            return None
        try:
            info = json.loads(marker.read_text())
        except (OSError, ValueError) as exc:
            raise SnapshotError(f"{marker} is not readable: {exc}") from exc
        if info.get("kind") != MARK or not isinstance(info.get("id"), str):
            raise SnapshotError(f"{path} holds a folder.json that is not a kiwi snapshot folder's")
        if int(info.get("format", 0)) > FORMAT:
            raise SnapshotError(
                f"{path} was made by a newer version (format {info['format']}); update the app"
            )
        return cls(path, info["id"])

    @classmethod
    def create(cls, path: Path, passphrase: str) -> Folder:
        """Make `path` a new snapshot folder, encrypted with `passphrase`."""
        if (path / FOLDER_FILE).exists():
            raise SnapshotError(f"{path} is a snapshot folder already")
        if path.exists() and any(p for p in path.iterdir() if not p.name.startswith(".")):
            raise SnapshotError(f"{path} is not empty; choose an empty or a new folder")
        path.mkdir(parents=True, exist_ok=True)
        folder_id = os.urandom(16).hex()
        salt = os.urandom(32).hex()
        part = path / (CHECK_FILE + ".part")
        crypt.encrypt_bytes(json.dumps({"id": folder_id, "salt": salt}).encode(), part, passphrase)
        _replace_from_part(part, path / CHECK_FILE)
        marker = path / (FOLDER_FILE + ".part")
        marker.write_text(json.dumps({"format": FORMAT, "kind": MARK, "id": folder_id}) + "\n")
        _replace_from_part(marker, path / FOLDER_FILE)
        (path / ITEMS).mkdir(exist_ok=True)
        folder = cls(path, folder_id)
        folder._set_unlocked(passphrase, salt)
        return folder

    def unlock(self, passphrase: str) -> None:
        """Check `passphrase` against check.gpg; raises BadPassphrase."""
        known = Folder._unlocked.get(self.id)
        if known and known[0] == passphrase:
            self._set_unlocked(*known)
            return
        check = self.path / CHECK_FILE
        if not check.is_file():
            raise SnapshotError(f"{check} is missing; the folder is not complete (still syncing?)")
        info = json.loads(crypt.decrypt_bytes(check, passphrase))
        if info.get("id") != self.id:
            raise SnapshotError("check.gpg belongs to another snapshot folder")
        self._set_unlocked(passphrase, info["salt"])

    def _set_unlocked(self, passphrase: str, salt: str) -> None:
        self._passphrase = passphrase
        self._salt = bytes.fromhex(salt)
        Folder._unlocked[self.id] = (passphrase, salt)

    @classmethod
    def forget_unlocked(cls, folder_id: str | None = None) -> None:
        if folder_id is None:
            cls._unlocked.clear()
        else:
            cls._unlocked.pop(folder_id, None)

    @property
    def unlocked(self) -> bool:
        return self._passphrase is not None

    def _pass(self) -> str:
        if self._passphrase is None:
            raise SnapshotError("the snapshot folder is locked")
        return self._passphrase

    # ---------------------------------------------------------------- layout
    def key(self, kind: str, item: str) -> str:
        if self._salt is None:
            raise SnapshotError("the snapshot folder is locked")
        return hmac.new(self._salt, f"{kind}:{item}".encode(), hashlib.sha256).hexdigest()[:32]

    def item_dir(self, kind: str, item: str) -> Path:
        return self.path / ITEMS / self.key(kind, item)

    def _cache_dir(self) -> Path:
        return paths.cache_dir() / "snapshot-meta" / self.id

    def snap_file(self, meta: Meta) -> Path:
        return self.item_dir(meta.kind, meta.item) / f"{meta.id}{_SNAP}"

    def meta_file(self, meta: Meta) -> Path:
        return self.item_dir(meta.kind, meta.item) / f"{meta.id}{_META}"

    # ----------------------------------------------------------------- write
    def write(
        self,
        *,
        kind: str,
        item: str,
        name: str,
        device: str,
        device_id: str,
        parent: str | None,
        ancestors: list[str],
        app: str,
        version: str,
        fill: Callable[[tarfile.TarFile], None],
        extra: dict | None = None,
        aside: bool = False,
    ) -> Meta:
        """Write one snapshot: the archive `fill` makes, then its meta."""
        passphrase = self._pass()
        directory = self.item_dir(kind, item)
        directory.mkdir(parents=True, exist_ok=True)
        sid = os.urandom(8).hex()
        snap = directory / f"{sid}{_SNAP}"
        part = directory / f"{sid}{_SNAP}.part"
        crypt.encrypt_tar(part, passphrase, fill)
        size, sha = _digest(part)
        _replace_from_part(part, snap)
        meta = Meta(
            id=sid,
            kind=kind,
            item=item,
            name=name,
            device=device,
            device_id=device_id,
            created=_now(),
            parent=parent,
            ancestors=ancestors[:ANCESTORS],
            size=size,
            sha256=sha,
            app=app,
            version=version,
            extra=extra or {},
            aside=aside,
        )
        mpart = directory / f"{sid}{_META}.part"
        try:
            crypt.encrypt_bytes(meta.to_json(), mpart, passphrase)
        except BaseException:
            snap.unlink(missing_ok=True)
            raise
        _replace_from_part(mpart, directory / f"{sid}{_META}")
        self._cache_put(meta)
        return meta

    # ------------------------------------------------------------------ read
    def _cache_get(self, sid: str) -> Meta | None:
        path = self._cache_dir() / f"{sid}.json"
        try:
            return Meta.from_json(path.read_text())
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def _cache_put(self, meta: Meta) -> None:
        directory = self._cache_dir()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = directory / f"{meta.id}.json.tmp"
        tmp.write_bytes(meta.to_json())
        tmp.replace(directory / f"{meta.id}.json")

    def _cache_drop(self, sid: str) -> None:
        (self._cache_dir() / f"{sid}.json").unlink(missing_ok=True)

    def metas(self, kind: str | None = None, item: str | None = None) -> list[Meta]:
        """Every complete snapshot in the folder (or of one item), newest first.

        Metas never change, so a decrypted one is cached in the cache directory; the
        rest are decrypted several at a time (a new device reads them all once)."""
        passphrase = self._pass()
        if item is not None and kind is not None:
            directories = [self.item_dir(kind, item)]
        else:
            root = self.path / ITEMS
            directories = sorted(d for d in root.iterdir() if d.is_dir()) if root.is_dir() else []
        found: list[Meta] = []
        pending: list[tuple[Path, Path]] = []
        for directory in directories:
            if not directory.is_dir():
                continue
            for entry in directory.iterdir():
                name = entry.name
                if not name.endswith(_META) or not _SID.match(name[: -len(_META)]):
                    continue  # a .part, a sync client's conflict copy, anything else
                sid = name[: -len(_META)]
                cached = self._cache_get(sid)
                if cached is not None:
                    found.append(cached)
                else:
                    pending.append((directory, entry))

        def read(job: tuple[Path, Path]) -> Meta | None:
            directory, entry = job
            try:
                meta = Meta.from_json(crypt.decrypt_bytes(entry, passphrase))
            except (SnapshotError, ValueError, TypeError, KeyError):
                self.unreadable.append(entry)
                return None
            if self.key(meta.kind, meta.item) != directory.name or meta.id != entry.name[:16]:
                self.unreadable.append(entry)  # a file moved to where it does not belong
                return None
            self._cache_put(meta)
            return meta

        if pending:
            with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
                found += [m for m in pool.map(read, pending) if m is not None]
        if kind is not None:
            found = [m for m in found if m.kind == kind]
        if item is not None:
            found = [m for m in found if m.item == item]
        return sorted(found, key=lambda m: (m.created, m.id), reverse=True)

    def ready(self, meta: Meta) -> bool:
        """Its data is here and as large as it should be (a sync client may still be
        bringing it)."""
        snap = self.snap_file(meta)
        try:
            return snap.stat().st_size == meta.size
        except OSError:
            return False

    def extract(self, meta: Meta, dest: Path) -> None:
        """Unpack a snapshot into `dest`, after checking it is the file the meta
        describes."""
        if not self.ready(meta):
            raise NotReady(
                f"the snapshot of {meta.name} from {meta.device} has not fully arrived yet; "
                "wait for the sync to finish"
            )
        snap = self.snap_file(meta)
        size, sha = _digest(snap)
        if size != meta.size or not hmac.compare_digest(sha, meta.sha256):
            raise SnapshotError(f"the snapshot of {meta.name} from {meta.device} is damaged")
        crypt.decrypt_tar(snap, self._pass(), dest)

    # ---------------------------------------------------------------- remove
    def remove(self, meta: Meta) -> None:
        self.meta_file(meta).unlink(missing_ok=True)  # the meta first: no half snapshot
        self.snap_file(meta).unlink(missing_ok=True)
        self._cache_drop(meta.id)

    def prune(self, kind: str, item: str, keep: int) -> list[Meta]:
        """Delete all but `keep` snapshots of an item: the newest of every line
        always stays (whatever two devices' clocks say), then the newest others."""
        metas = self.metas(kind, item)
        keepers = [m.id for m in heads(metas)]
        for meta in metas:
            if len(keepers) >= max(keep, 1):
                break
            if meta.id not in keepers:
                keepers.append(meta.id)
        old = [m for m in metas if m.id not in keepers]
        for meta in old:
            self.remove(meta)
        return old

    def forget(self, kind: str, item: str) -> int:
        """Delete every snapshot of an item; returns how many there were."""
        metas = self.metas(kind, item)
        for meta in metas:
            self._cache_drop(meta.id)
        shutil.rmtree(self.item_dir(kind, item), ignore_errors=True)
        return len(metas)

    # ----------------------------------------------------------------- in use
    def mark_in_use(self, kind: str, item: str, device_id: str, device: str) -> None:
        directory = self.item_dir(kind, item)
        directory.mkdir(parents=True, exist_ok=True)
        part = directory / f"{_INUSE}{device_id}.gpg.part"
        body = {"device": device, "since": _now().isoformat()}
        crypt.encrypt_bytes(json.dumps(body).encode(), part, self._pass())
        _replace_from_part(part, directory / f"{_INUSE}{device_id}.gpg")

    def clear_in_use(self, kind: str, item: str, device_id: str) -> None:
        (self.item_dir(kind, item) / f"{_INUSE}{device_id}.gpg").unlink(missing_ok=True)

    def in_use_elsewhere(
        self, kind: str, item: str, device_id: str
    ) -> list[tuple[str, dt.datetime]]:
        """Other devices that say they are using the item: (device, since)."""
        directory = self.item_dir(kind, item)
        out = []
        if not directory.is_dir():
            return out
        for entry in directory.glob(f"{_INUSE}*.gpg"):
            if entry.name == f"{_INUSE}{device_id}.gpg":
                continue
            try:
                body = json.loads(crypt.decrypt_bytes(entry, self._pass()))
                out.append((body["device"], dt.datetime.fromisoformat(body["since"])))
            except (SnapshotError, ValueError, KeyError):
                continue
        return out
