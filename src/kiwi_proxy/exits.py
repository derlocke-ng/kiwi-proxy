"""Load and save exits. One directory per exit, JSON on disk; passwords in secrets.

An exit made with the CLI gets a fresh id. A consumer that registers its own — kiwi-fox
for a browser identity — passes its own id (the profile id), so the gateway keeps the
name it always had and the consumer can find the exit again without a lookup table.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import uuid
from pathlib import Path

from . import paths, providers, secrets
from .models import DnsConfig, Endpoint, Exit, Expose, ProviderRecord


class ExitError(RuntimeError):
    pass


def _write_json(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload)
    tmp.replace(path)


def valid_name(name: str) -> bool:
    """Anything a person would type, but never a path or an option."""
    return bool(name.strip()) and "/" not in name and not name.startswith("-") and len(name) <= 64


def module_endpoint(module: str, *, lease: str | None, country: str | None) -> Endpoint:
    """A module-backed endpoint. Nothing is started: the gateway brings the provider
    up when the exit comes up, on the providers bridge."""
    if not providers.is_installed(module):
        raise providers.ProviderError(f"provider module {module!r} is not installed")
    _prov, manifest = providers.load(module)
    if not manifest.runs_container:
        raise providers.ProviderError(
            f"{module!r} does not produce its own endpoint; give an endpoint"
        )
    return Endpoint(
        host=paths.provider_static_ip(module, lease),
        port=manifest.socks_port,
        module=module,
        lease=lease or None,
        country=country or None,
    )


def make_expose(
    bind: str, port: int, *, username: str | None, password: str | None, allow_open: bool
) -> Expose:
    """A host listener, checked the same way for the CLI and the GUI: a port, a
    password whenever there is a user, and a password — or an explicit yes — for
    an address other machines can reach."""
    if not 0 < port < 65536:
        raise ValueError(f"{port} is not a port")
    if username and not password:
        raise ValueError("a host port with a user needs a password")
    ex = Expose(
        bind=bind or "127.0.0.1", port=port, username=username or None, has_password=bool(password)
    )
    if not ex.loopback and not ex.username and not allow_open:
        raise ValueError(
            f"{ex.address} is reachable from other machines; protect it with a user and "
            "password, or say that it may be open"
        )
    return ex


def create(
    name: str,
    endpoint: Endpoint,
    *,
    password: str | None = None,
    dns: DnsConfig | None = None,
    expose: Expose | None = None,
    expose_password: str | None = None,
    owner: str | None = None,
    exit_id: str | None = None,
    notes: str = "",
) -> Exit:
    if not valid_name(name):
        raise ExitError(f"{name!r} is not a usable exit name")
    if find_by_name(name):
        raise ExitError(f"an exit named {name!r} already exists")
    if exit_id and (paths.exit_dir(exit_id) / "exit.json").exists():
        raise ExitError(f"an exit with id {exit_id!r} already exists")
    ex = Exit(
        id=exit_id or str(uuid.uuid4()),
        name=name,
        created=dt.datetime.now(dt.UTC),
        endpoint=endpoint,
        dns=dns or DnsConfig(),
        expose=expose,
        owner=owner,
        notes=notes,
    )
    save(ex)
    if password:
        secrets.store(ex.id, password, kind="endpoint", label=f"kiwi-proxy {name}")
    if expose_password:
        secrets.store(ex.id, expose_password, kind="expose", label=f"kiwi-proxy {name} (host)")
    return ex


def save(ex: Exit) -> None:
    _write_json(paths.exit_dir(ex.id) / "exit.json", ex.model_dump_json(indent=2))


def load(exit_id: str) -> Exit:
    path = paths.exit_dir(exit_id) / "exit.json"
    if not path.exists():
        raise ExitError(f"no such exit {exit_id!r}")
    return Exit.model_validate_json(path.read_text())


def exists(exit_id: str) -> bool:
    return (paths.exit_dir(exit_id) / "exit.json").exists()


def list_exits() -> list[Exit]:
    root = paths.exits_dir()
    if not root.exists():
        return []
    out = []
    for d in sorted(root.iterdir()):
        if (d / "exit.json").exists():
            try:
                out.append(load(d.name))
            except Exception:  # noqa: BLE001 - a broken exit must not hide the others
                continue
    return sorted(out, key=lambda e: e.name)


def find_by_name(name: str) -> Exit | None:
    return next((e for e in list_exits() if e.name == name), None)


def resolve_ref(ref: str) -> Exit:
    """Accept a name or an id prefix, the way git accepts a short sha."""
    if found := find_by_name(ref):
        return found
    matches = [e for e in list_exits() if e.id.startswith(ref)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ExitError(f"no exit matches {ref!r}")
    raise ExitError(f"{ref!r} is ambiguous: {[e.name for e in matches]}")


def delete(exit_id: str) -> None:
    secrets.clear(exit_id)
    shutil.rmtree(paths.exit_dir(exit_id), ignore_errors=True)


def record_exit(ex: Exit, info) -> None:
    ex.last_exit = info
    if exists(ex.id):
        save(ex)


# ------------------------------------------------------------ provider cache
def load_providers() -> list[ProviderRecord]:
    path = paths.providers_cache()
    if not path.exists():
        return []
    return [ProviderRecord.model_validate(r) for r in json.loads(path.read_text())]


def record_provider(record: ProviderRecord) -> None:
    """Provider-reported geo is self-reported; this is what we measured."""
    kept = [
        r for r in load_providers() if not (r.module == record.module and r.lease == record.lease)
    ]
    kept.append(record)
    _write_json(
        paths.providers_cache(),
        json.dumps([json.loads(r.model_dump_json()) for r in kept], indent=2),
    )
