"""What Kiwi Proxy puts into snapshots: exits, and module settings.

An **exit** snapshot holds its ``exit.json`` and both of its passwords (the
upstream's and the host listener's). A **module** snapshot holds the module's state
folder (a Mysterium keystore and identity, for example) and its podman secrets (the
keystore's passphrase), minus what the module calls rebuildable
(``snapshot_exclude`` on its provider class, read with getattr so older modules work).

Restoring never happens under a running gateway or a running provider, and never
over a different exit of the same name.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import tarfile
from pathlib import Path

from .. import exits, gateway, paths, podman, providers, secrets
from ..models import Exit
from . import Meta, SnapshotError, add_bytes, auto, folder, restore, take

EXIT = "exit"
MODULE = "module"


# ------------------------------------------------------------------- exits
def _exit_fill(ex: Exit):
    def fill(tar: tarfile.TarFile) -> None:
        add_bytes(tar, "exit.json", (paths.exit_dir(ex.id) / "exit.json").read_bytes())
        passwords = {kind: secrets.lookup(ex.id, kind=kind) for kind in secrets.KINDS}
        add_bytes(tar, "secrets.json", json.dumps(passwords).encode())

    return fill


def _exit_extra(ex: Exit) -> dict:
    return {"label": ex.endpoint.label, "module": ex.endpoint.module, "owner": ex.owner}


def take_exit(ex: Exit, *, aside: bool = False, supersede: list[Meta] | None = None) -> Meta:
    return take(
        EXIT,
        ex.id,
        ex.name,
        _exit_fill(ex),
        extra=_exit_extra(ex),
        aside=aside,
        supersede=supersede,
    )


def auto_exit(ex: Exit) -> str | None:
    """The automatic snapshot after an exit was created or changed."""
    if not exits.exists(ex.id):
        return None
    return auto(EXIT, ex.id, ex.name, _exit_fill(ex), extra=_exit_extra(ex))


def restore_exit(item: str, sid: str) -> Exit:
    """Restore exit `item` (its id) from snapshot `sid`. Refused while its gateway
    is up, and when another exit here already has its name."""
    here = exits.exists(item)
    if here and gateway.is_up(item):
        raise SnapshotError(f"{exits.load(item).name} is up; take it down first")

    def apply(staging: Path, meta: Meta) -> None:
        restored = Exit.model_validate_json((staging / "exit.json").read_text())
        if restored.id != meta.item:
            raise SnapshotError("the snapshot holds a different exit than it says")
        if gateway.is_up(restored.id):
            raise SnapshotError(f"{restored.name} is up; take it down first")
        clash = exits.find_by_name(restored.name)
        if clash and clash.id != restored.id:
            raise SnapshotError(
                f"an exit named {restored.name} already exists here; rename one of them first"
            )
        passwords = json.loads((staging / "secrets.json").read_text())
        exits.save(restored)
        secrets.clear(restored.id)
        for kind, value in passwords.items():
            if value and kind in secrets.KINDS:
                label = f"kiwi-proxy {restored.name}" + (" (host)" if kind == "expose" else "")
                secrets.store(restored.id, value, kind=kind, label=label)

    keep = (lambda: take_exit(exits.load(item), aside=True)) if here else None
    restore(EXIT, item, sid, apply, here=here, keep_current=keep)
    return exits.load(item)


# ----------------------------------------------------------------- modules
def _module_secret_prefix(name: str) -> str:
    return f"{paths.PREFIX}-mod-{name}-"


def _module_excludes(name: str) -> tuple[str, ...]:
    try:
        prov, _manifest = providers.load(name)
    except providers.ProviderError:
        return ()
    return tuple(getattr(prov, "snapshot_exclude", ()) or ())


def _excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    return any(
        relative == p or relative.startswith(p.rstrip("/") + "/") or fnmatch.fnmatch(relative, p)
        for p in patterns
    )


def module_secrets(name: str) -> dict[str, str]:
    """The module's podman secrets, by key (the part after kf-mod-<name>-)."""
    prefix = _module_secret_prefix(name)
    if not podman.available():
        return {}
    return {n[len(prefix) :]: podman.secret_value(n) for n in podman.secret_names(prefix)}


def _module_fill(name: str):
    state = paths.module_state_dir(name)
    patterns = _module_excludes(name)

    def keep(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        relative = info.name.removeprefix("state").lstrip("/")
        return None if relative and _excluded(relative, patterns) else info

    def fill(tar: tarfile.TarFile) -> None:
        if state.is_dir():
            tar.add(state, arcname="state", filter=keep)
        add_bytes(tar, "secrets.json", json.dumps(module_secrets(name)).encode())

    return fill


def _kept_files(name: str) -> bool:
    """The module's state holds a file a snapshot would carry (not only caches)."""
    state = paths.module_state_dir(name)
    if not state.is_dir():
        return False
    patterns = _module_excludes(name)
    return any(
        p.is_file() and not _excluded(str(p.relative_to(state)), patterns) for p in state.rglob("*")
    )


def _secret_names() -> list[str]:
    """Every module secret, in one podman call."""
    return podman.secret_names(f"{paths.PREFIX}-mod-") if podman.available() else []


def module_has_state(name: str, secret_names: list[str] | None = None) -> bool:
    """The module has settings worth a snapshot: files it does not rebuild, or a
    secret."""
    names = _secret_names() if secret_names is None else secret_names
    prefix = _module_secret_prefix(name)
    return _kept_files(name) or any(n.startswith(prefix) for n in names)


def take_module(name: str, *, aside: bool = False) -> Meta:
    return take(MODULE, name, name, _module_fill(name), extra={"module": name}, aside=aside)


def auto_module(name: str) -> str | None:
    """The automatic snapshot after a module was configured."""
    return auto(MODULE, name, name, _module_fill(name), extra={"module": name})


def _module_running(name: str) -> bool:
    if not podman.available():
        return False
    return any(
        (c.get("State") or "").lower() == "running"
        for c in podman.ps(labels={paths.MODULE_LABEL: name})
        if (c.get("Labels") or {}).get(paths.ROLE_LABEL) in ("provider", "tunnel", "adapter")
    )


def restore_module(name: str, sid: str) -> None:
    """Restore a module's settings: its state folder and its secrets. Refused while
    the module's containers run."""
    if _module_running(name):
        raise SnapshotError(f"{name} is running; take its exits down first")
    target = paths.module_state_dir(name)
    here = module_has_state(name)

    def apply(staging: Path, _meta: Meta) -> None:
        if _module_running(name):
            raise SnapshotError(f"{name} is running; take its exits down first")
        incoming = staging / "state"
        incoming.mkdir(exist_ok=True)
        old = target.with_name(f".{target.name}.old-{os.urandom(4).hex()}")
        if target.exists():
            os.rename(target, old)
        try:
            os.rename(incoming, target)
        except OSError:
            if old.exists():
                os.rename(old, target)
            raise
        shutil.rmtree(old, ignore_errors=True)
        values = json.loads((staging / "secrets.json").read_text())
        prefix = _module_secret_prefix(name)
        for key, value in values.items():
            podman.secret_set(prefix + key, value)

    keep = (lambda: take_module(name, aside=True)) if here else None
    paths.modules_state_dir().mkdir(parents=True, exist_ok=True)
    restore(MODULE, name, sid, apply, here=here, keep_current=keep, staging_root=paths.data_dir())


# ---------------------------------------------------------------- lookups
def local_items() -> dict[tuple[str, str], str]:
    """Kiwi Proxy's items on this device: (kind, id) -> name."""
    found: dict[tuple[str, str], str] = {(EXIT, ex.id): ex.name for ex in exits.list_exits()}
    names = _secret_names()
    for name in providers.discover():
        if module_has_state(name, names):
            found[(MODULE, name)] = name
    return found


def find_in_folder(ref: str) -> tuple[str, str, str]:
    """An exit or `module:NAME` named in the folder: (kind, item id, name). For an
    exit that is not on this device."""
    if ref.startswith("module:"):
        name = ref.split(":", 1)[1]
        return MODULE, name, name
    metas = [m for m in folder().metas() if m.kind == EXIT]
    named = [m for m in metas if m.name == ref]
    if not named:
        named = [m for m in metas if m.item.startswith(ref)]
    items = {m.item for m in named}
    if not items:
        raise SnapshotError(f"no exit {ref!r} in the snapshot folder")
    if len(items) > 1:
        raise SnapshotError(f"{ref!r} names {len(items)} different exits in the folder; use its id")
    meta = named[0]
    return EXIT, meta.item, meta.name
