"""Where everything lives on disk, and what every podman object is called.

XDG, user scope only — no root anywhere.

Podman object names keep the ``kf-`` prefix they had inside kiwi-fox (``kf-gw-…``,
``kf-prov-…``, the ``kf-providers`` bridge, ``kf-creds-…`` secrets). That is
deliberate: a rootless podman refuses to create a second network on a subnet that
is already in use, so renaming the bridge would strand every host that ran kiwi-fox
before the split, and gateways started by an older kiwi-fox stay recognisable.
What a container *is* is said by labels (``kiwi-proxy.role`` and friends), never by
its name.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

APP = "kiwi-proxy"
PREFIX = "kf"  # every podman object name starts with this (see the module docstring)

# Every container kiwi-proxy starts carries kiwi-proxy.role, so this one filter
# finds all of them whichever app asked for it (the "app" label is the consumer's).
ROLE_LABEL = "kiwi-proxy.role"  # gateway | provider | tunnel | adapter
EXIT_LABEL = "kiwi-proxy.exit"  # exit id, on a gateway
MODULE_LABEL = "kiwi-proxy.module"  # provider module, on a gateway or provider
LEASE_LABEL = "kiwi-proxy.lease"  # provider lease, on a gateway or provider
CONFIG_LABEL = "kiwi-proxy.config"  # hash of what a gateway was started with
EXPOSE_LABEL = "kiwi-proxy.expose"  # host address its SOCKS5 is published on
FILTER = f"label={ROLE_LABEL}"

GATEWAY_IMAGE = f"{APP}/gateway:latest"


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / APP


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / APP


def cache_dir() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache") / APP


def runtime_dir() -> Path:
    rt = os.environ.get("XDG_RUNTIME_DIR")
    return Path(rt) / APP if rt else cache_dir() / "run"


def exits_dir() -> Path:
    return data_dir() / "exits"


def exit_dir(exit_id: str) -> Path:
    return exits_dir() / exit_id


def exit_runtime_dir(exit_id: str) -> Path:
    """Generated per-gateway files (resolver config, resolv.conf for joiners)."""
    d = runtime_dir() / "exits" / exit_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def holds_dir() -> Path:
    """One empty file per exit someone brought up on purpose (`kiwi-proxy up`), so
    a consumer finishing with it does not tear it down under them."""
    return runtime_dir() / "holds"


def blocklists_dir() -> Path:
    return data_dir() / "blocklists"


def providers_cache() -> Path:
    return data_dir() / "providers.json"


def secrets_dir() -> Path:
    """The file fallback of the secret store, for hosts without a Secret Service."""
    return config_dir() / "secrets"


def modules_dir() -> Path:
    """Where provider plugins are installed, one directory per module (tor, vpn,
    9proxy, mysterium). kiwi-updater drops each module's package here; kiwi-proxy
    discovers them by scanning this directory."""
    return data_dir() / "modules"


def module_dir(name: str) -> Path:
    return modules_dir() / name


def modules_state_dir() -> Path:
    """Per-module writable runtime state (leases, caches, account config), kept out
    of the read-only installed module directory."""
    return data_dir() / "modules-state"


def module_state_dir(name: str) -> Path:
    return modules_state_dir() / name


# The shared podman network local provider containers and the gateways that use
# them attach to, so a gateway can reach its provider's SOCKS5 while its own
# nftables still permits exactly one destination. Plain (already-remote) SOCKS5
# endpoints never touch it; those gateways stay on pasta.
PROVIDERS_NETWORK = f"{PREFIX}-providers"
# Created with a fixed subnet so providers get deterministic static addresses: a
# gateway's firewall pin then stays valid across a provider restart, and a freed
# address cannot be handed to a different container. Picked high in 10.x to avoid
# podman's usual auto-allocated ranges.
PROVIDERS_SUBNET = "10.89.231.0/24"
PROVIDERS_GATEWAY_IP = "10.89.231.1"


def provider_static_ip(name: str, lease: str | None = None) -> str:
    """A deterministic address in PROVIDERS_SUBNET for a module+lease, so the same
    provider always comes up on the same IP. Uses a stable hash (not Python's
    salted hash()) over the host octet range .2–.254."""
    key = f"{name}:{lease or ''}".encode()
    octet = 2 + int(hashlib.sha256(key).hexdigest(), 16) % 253  # 2..254
    prefix = PROVIDERS_SUBNET.rsplit(".", 1)[0]  # "10.89.231"
    return f"{prefix}.{octet}"


def provider_image(name: str) -> str:
    return f"{APP}/{name}:latest"


def _container_safe(raw: str) -> str:
    # Container names allow only [a-zA-Z0-9._-]; a lease like a 9proxy port or a
    # myst provider id is already in that set, but be defensive. isalnum() is
    # Unicode-aware and would pass e.g. accented letters podman rejects, so gate
    # on ASCII first.
    return "".join(c if (c.isascii() and c.isalnum()) or c in "._-" else "-" for c in raw)[:63]


def provider_container_name(name: str, lease: str | None = None) -> str:
    """A provider container is shared across every exit that uses the same
    module+lease, so its name is keyed on those, not on an exit id."""
    suffix = f"-{lease}" if lease else ""
    return _container_safe(f"{PREFIX}-prov-{name}{suffix}")


def gateway_name(exit_id: str) -> str:
    """kiwi-fox's exits use the profile id as exit id, so this is the same name its
    gateways always had (kf-gw-<profile id[:12]>)."""
    return f"{PREFIX}-gw-{exit_id[:12]}"


def creds_secret_name(exit_id: str) -> str:
    return f"{PREFIX}-creds-{exit_id[:12]}"


def expose_secret_name(exit_id: str) -> str:
    return f"{PREFIX}-expose-{exit_id[:12]}"


def ensure_tree() -> None:
    for d in (
        data_dir(),
        config_dir(),
        exits_dir(),
        blocklists_dir(),
        modules_dir(),
        modules_state_dir(),
        runtime_dir(),
    ):
        d.mkdir(parents=True, exist_ok=True)
