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

from . import countries, paths, providers, secrets
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


def where(ex: Exit) -> str:
    """An exit's upstream in one line: its label, and the lease or country when
    they say something the label does not (not a VPN exit's own id, not a 9proxy
    port the label already shows)."""
    out = ex.endpoint.label
    lease = ex.endpoint.lease
    if lease and lease != ex.id and not out.endswith(f":{lease}"):
        return f"{out} ({lease})"
    if ex.endpoint.country:
        return f"{out} ({ex.endpoint.country.upper()})"
    return out


def set_config(ex: Exit, text: str) -> str:
    """Give a module exit its own config (a VPN: its WireGuard or OpenVPN file):
    checked by the module, kept whole as the exit's secret, and the exit keyed to
    a provider container of its own. Returns the module's few words on it."""
    module = ex.endpoint.module
    if not module:
        raise ExitError(f"exit {ex.name!r} has no module to give a config to")
    summary = providers.check_config(module, text)
    secrets.store(ex.id, text, kind="vpnconfig", label=f"kiwi-proxy {ex.name} config")
    ex.endpoint.lease = ex.id
    # Labelled by the server the config connects to (vpn:203.0.113.4:51820), not
    # by an address on the providers bridge that means nothing to anyone.
    server = getattr(providers.get_provider(module), "config_server", None)
    found = server(text) if callable(server) else None
    if found:
        ex.endpoint.host, ex.endpoint.port = found
    else:
        ex.endpoint.host = paths.provider_static_ip(module, ex.id)
    save(ex)
    return summary


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
    if country and not countries.is_code(country):
        raise ExitError(
            f"--country takes a two-letter code, not {country!r}: "
            f"`kiwi-proxy module countries {module}` lists them"
        )
    prov = providers.get_provider(module)
    assign = getattr(prov, "assign_lease", None)
    port = manifest.socks_port
    if callable(assign):
        # A module whose leases are handed out (a 9proxy port per exit): the next
        # free one, unless one was asked for.
        if not lease:
            taken = [e.endpoint.lease for e in list_exits() if e.endpoint.module == module]
            lease = assign(providers.context_for(module, manifest), [t for t in taken if t])
        if str(lease).isdigit():
            port = int(lease)
    return Endpoint(
        host=paths.provider_static_ip(module, None if callable(assign) else lease),
        port=port,
        module=module,
        lease=lease or None,
        country=country.lower() if country else None,
    )


def default_socks_auth(endpoint: Endpoint) -> str:
    """Passthrough on an isolation provider (tor), inject everywhere else. On tor
    the exit has a token to put in front, a no-auth client in the namespace still
    gets that token, and a client that brings its own SOCKS credentials — Tor
    Browser — keeps a circuit per site. So one exit serves every kind of member,
    and nothing has to be flipped for Tor Browser later."""
    try:
        if providers.manages(endpoint.module) and providers.manifest_of(endpoint.module).auth == (
            "isolation"
        ):
            return "passthrough"
    except providers.ProviderError:
        pass
    return "inject"


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


def _new_exit_dns() -> DnsConfig:
    from . import prefs  # late: prefs imports dns, which may import this module

    return prefs.new_exit_dns()


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
    socks_auth: str | None = None,
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
        dns=dns or _new_exit_dns(),
        expose=expose,
        socks_auth=socks_auth or default_socks_auth(endpoint),  # type: ignore[arg-type]
        owner=owner,
        notes=notes,
    )
    save(ex)
    if password:
        secrets.store(ex.id, password, kind="endpoint", label=f"kiwi-proxy {name}")
    if expose_password:
        secrets.store(ex.id, expose_password, kind="expose", label=f"kiwi-proxy {name} (host)")
    return ex


# Endpoint fields written only when set, so an older kiwi-proxy (which forbids
# fields it does not know) still reads an exit that uses none of them.
_OMIT_EMPTY = ("only_countries", "only_nodes", "never_countries", "options")


def save(ex: Exit) -> None:
    data = ex.model_dump(mode="json")
    for key in _OMIT_EMPTY:
        if not data["endpoint"].get(key):
            data["endpoint"].pop(key, None)
    _write_json(paths.exit_dir(ex.id) / "exit.json", json.dumps(data, indent=2))


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
