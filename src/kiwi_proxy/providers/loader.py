"""Discover and load provider modules installed under paths.modules_dir().

A module is a directory holding a ``provider.py`` that exposes ``PROVIDER`` (a
Provider) and ``MANIFEST`` (a ProviderManifest). It is loaded by file path, not by
import name, so a module directory may start with a digit (``9proxy``) — which is
not a legal Python identifier and could never be ``import``ed normally.
"""

from __future__ import annotations

import importlib.util
import re

from .. import paths, podman
from ..models import ProviderManifest
from .base import Provider, ProviderContext, ProviderError

_SYNTH_RE = re.compile(r"[^0-9a-zA-Z_]")
# A module name is a single path segment in a safe charset: no separators, no
# "..", so a name can never escape modules_dir() to load an arbitrary provider.py.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def valid_name(name: str) -> bool:
    return bool(name) and name != ".." and "/" not in name and bool(_NAME_RE.match(name))


def discover() -> list[str]:
    """Installed module names, each a directory under modules_dir() with a
    provider.py."""
    root = paths.modules_dir()
    if not root.exists():
        return []
    return sorted(
        d.name
        for d in root.iterdir()
        if d.is_dir() and (d / "provider.py").exists() and not d.name.startswith(".")
    )


def is_installed(name: str) -> bool:
    return valid_name(name) and (paths.module_dir(name) / "provider.py").exists()


def load(name: str) -> tuple[Provider, ProviderManifest]:
    """Import a module's provider.py and return its (PROVIDER, MANIFEST)."""
    if not valid_name(name):
        raise ProviderError(f"invalid provider module name {name!r}")
    path = paths.module_dir(name) / "provider.py"
    if not path.exists():
        raise ProviderError(f"provider module {name!r} is not installed ({path} missing)")
    synth = "kiwi_proxy_module_" + _SYNTH_RE.sub("_", name)
    spec = importlib.util.spec_from_file_location(synth, path)
    if spec is None or spec.loader is None:
        raise ProviderError(f"{name}: could not load {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise ProviderError(f"{name}: provider.py failed to import: {exc}") from exc

    provider = getattr(module, "PROVIDER", None)
    if provider is None:
        raise ProviderError(f"{name}: provider.py defines no PROVIDER")
    manifest = getattr(module, "MANIFEST", None) or getattr(provider, "manifest", None)
    if manifest is None:
        raise ProviderError(f"{name}: provider.py exposes no MANIFEST")
    if not isinstance(manifest, ProviderManifest):
        raise ProviderError(f"{name}: MANIFEST is not a ProviderManifest")
    if manifest.name != name:
        raise ProviderError(
            f"module directory {name!r} does not match manifest name {manifest.name!r}"
        )
    if not isinstance(provider, Provider):
        raise ProviderError(f"{name}: PROVIDER does not satisfy the Provider interface")
    return provider, manifest


def get_provider(name: str) -> Provider:
    return load(name)[0]


def manifest_of(name: str) -> ProviderManifest:
    return load(name)[1]


def context_for(name: str, manifest: ProviderManifest | None = None) -> ProviderContext:
    """Build the host-side context a provider is handed."""
    if manifest is None:
        manifest = manifest_of(name)
    image = manifest.image or paths.provider_image(name)
    state = paths.module_state_dir(name)
    state.mkdir(parents=True, exist_ok=True)
    return ProviderContext(
        name=name,
        module_dir=paths.module_dir(name),
        state_dir=state,
        network=paths.PROVIDERS_NETWORK,
        image=image,
        socks_port=manifest.socks_port,
    )


def manages(name: str | None) -> bool:
    """True when kiwi-proxy should manage this endpoint's provider lifecycle: the
    module is installed and runs its own container. A ``module`` tag for an
    uninstalled or remote-only provider is just a label on a plain SOCKS5 endpoint.
    """
    if not name or not is_installed(name):
        return False
    try:
        return manifest_of(name).runs_container
    except ProviderError:
        return False


def assigns_leases(name: str | None) -> bool:
    """Does the module hand out its leases itself (9proxy: the next free of its
    ten ports), so there is nothing for the user to choose?"""
    if not name or not is_installed(name):
        return False
    try:
        return callable(getattr(get_provider(name), "assign_lease", None))
    except ProviderError:
        return False


def account_state(name: str | None) -> tuple[bool, str] | None:
    """For a module that needs an account (its manifest says so, and it declares
    settings): (is it set, one line on it). None for a module that needs none."""
    if not name or not is_installed(name):
        return None
    try:
        prov, manifest = load(name)
        ctx = context_for(name, manifest)
        if not manifest.needs_account or not list(getattr(prov, "settings", lambda _c: [])(ctx)):
            return None
        state = prov.configured(ctx)
    except Exception:  # noqa: BLE001 - a row's text, not a command
        return None
    return (bool(state), state or "not set")


def exit_options(name: str | None) -> list:
    """What an exit on this module can also be chosen by, as Settings (key, title,
    help): 9proxy's state, city, zip code and plan. Empty for most modules."""
    if not name or not is_installed(name):
        return []
    try:
        prov, manifest = load(name)
        hook = getattr(prov, "exit_options", None)
        return list(hook(context_for(name, manifest))) if callable(hook) else []
    except Exception:  # noqa: BLE001 - rows in a dialog, not a command
        return []


def clean_options(name: str | None, given: dict[str, str]) -> dict[str, str]:
    """`given` with empty values dropped; a key the module does not have is an error."""
    known = {s.key for s in exit_options(name)}
    out = {}
    for key, value in given.items():
        if key not in known:
            have = ", ".join(sorted(known)) or "none"
            raise ProviderError(f"{name}: no option {key!r} (it has: {have})")
        if value.strip():
            out[key] = value.strip()
    return out


def keys_leases(name: str | None) -> bool:
    """Does the module name its provider containers itself, from more than the
    lease (Mysterium: the wallet and the node)?"""
    if not name or not is_installed(name):
        return False
    try:
        return callable(getattr(get_provider(name), "lease_key", None))
    except ProviderError:
        return False


def lease_key(name: str, lease: str | None, country: str | None, options: dict) -> str | None:
    """The module's key for the provider container of an exit with this lease,
    country and options."""
    prov, manifest = load(name)
    return prov.lease_key(
        context_for(name, manifest), lease=lease, country=country, options=options
    )


# ------------------------------------------------------------------ accounts
def has_accounts(name: str | None) -> bool:
    """Does the module hold accounts of its own (Mysterium: wallets)?"""
    if not name or not is_installed(name):
        return False
    try:
        return callable(getattr(get_provider(name), "accounts", None))
    except ProviderError:
        return False


def account_noun(name: str) -> str:
    """What the module calls one account: "wallet"; "account" when it does not say."""
    try:
        return getattr(get_provider(name), "account_noun", None) or "account"
    except ProviderError:
        return "account"


def _account_hook(name: str, hook: str):
    prov, manifest = load(name)
    fn = getattr(prov, hook, None)
    if not callable(fn):
        raise ProviderError(f"{name} has no {hook}")
    return fn, context_for(name, manifest)


def accounts(name: str, *, refresh: bool = False, only: str | None = None) -> list:
    """The module's accounts (``only``: that one). With ``refresh`` it asks for
    their state now (slow: Mysterium starts a node); without, it says what it
    last knew."""
    fn, ctx = _account_hook(name, "accounts")
    return list(fn(ctx, refresh=refresh, only=only))


def account_new_settings(name: str) -> list:
    fn, ctx = _account_hook(name, "account_new_settings")
    return list(fn(ctx))


def account_new(name: str, values: dict[str, str]) -> list[str]:
    fn, ctx = _account_hook(name, "account_new")
    return list(fn(ctx, values))


def account_history(name: str, account: str) -> list:
    fn, ctx = _account_hook(name, "account_history")
    return list(fn(ctx, account))


def account_act(name: str, account: str, action: str) -> list[str]:
    fn, ctx = _account_hook(name, "account_act")
    return list(fn(ctx, account, action))


def account_rename(name: str, account: str, new_name: str) -> None:
    fn, ctx = _account_hook(name, "account_rename")
    fn(ctx, account, new_name)


def account_export(name: str, account: str, dest: str) -> str:
    """Write the account's key file to ``dest`` (a folder or a file); the path."""
    fn, ctx = _account_hook(name, "account_export")
    return str(fn(ctx, account, dest))


def account_of(name: str, options: dict) -> str | None:
    """The account an exit with these options uses (its own choice or the
    module's default)."""
    fn, ctx = _account_hook(name, "account_of")
    return fn(ctx, dict(options or {}))


def account_users(name: str, account: str) -> list[str]:
    """The exits on this module that use the account."""
    from .. import exits

    out = []
    for ex in exits.list_exits():
        if ex.endpoint.module == name and account_of(name, ex.endpoint.options) == account:
            out.append(ex.name)
    return out


def account_remove(name: str, account: str) -> list[str]:
    """Remove an account no exit uses; the module keeps what it removes where it
    can be put back, and says where."""
    if users := account_users(name, account):
        raise ProviderError(
            f"{account_noun(name)} {account} is used by {', '.join(users)}; "
            "move those exits to another first"
        )
    fn, ctx = _account_hook(name, "account_remove")
    return list(fn(ctx, account))


def takes_config(name: str | None) -> bool:
    """Does an exit on this module need a config file of its own (a VPN: its
    WireGuard or OpenVPN config)?"""
    if not name or not is_installed(name):
        return False
    try:
        return callable(getattr(get_provider(name), "check_config", None))
    except ProviderError:
        return False


def check_config(name: str, text: str) -> str:
    """The module's few words on a config ("WireGuard · host:port"), or its
    ProviderError saying why it cannot be an exit. Nothing is stored or started."""
    check = getattr(get_provider(name), "check_config", None)
    if not callable(check):
        raise ProviderError(f"{name} takes no config file")
    return check(text)


def container_of(name: str, lease: str | None = None) -> str:
    """The container that serves a lease: one per lease, unless the module says
    otherwise (a 9proxy daemon serves every port, every exit, from one)."""
    prov, manifest = load(name)
    ctx = context_for(name, manifest)
    pick = getattr(prov, "container_for", None)
    return pick(ctx, lease) if callable(pick) else ctx.container_name(lease)


def lease_alive(name: str, lease: str | None = None) -> bool:
    """Is a lease served right now: its container running, and whatever else the
    module checks (a 9proxy port still bound to an IP)."""
    prov, manifest = load(name)
    alive = getattr(prov, "alive", None)
    if callable(alive):
        return bool(alive(context_for(name, manifest), lease))
    return podman.is_running(container_of(name, lease))


def config_sources(name: str) -> list:
    """Configs the module can find on this machine (vpn: NetworkManager's WireGuard
    and OpenVPN connections), as Leases: id, label, detail. Empty when it finds none
    or has no such hook."""
    prov, manifest = load(name)
    find = getattr(prov, "config_sources", None)
    return list(find(context_for(name, manifest))) if callable(find) else []


def config_from(name: str, source: str) -> str:
    """The config text of one of those sources, by id or label."""
    prov, manifest = load(name)
    get = getattr(prov, "config_from", None)
    if not callable(get):
        raise ProviderError(f"{name} finds no configs on this machine")
    return get(context_for(name, manifest), source)
