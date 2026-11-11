"""Provider plugin subsystem.

kiwi-proxy manages SOCKS5/VPN provider modules (tor, vpn, 9proxy, mysterium) that
each expose a ready SOCKS5 upstream for a gateway — and through the gateway for
kiwi-fox, kiwi-pentesting, host applications and kiwi-server machines. Modules are
discovered under paths.modules_dir() and loaded by file path.
"""

from __future__ import annotations

from .base import (
    ContainerProvider,
    Country,
    Node,
    Provider,
    ProviderContext,
    ProviderError,
    Setting,
    TunnelProvider,
    countries_for,
    leases_for,
)
from .loader import (
    check_config,
    context_for,
    discover,
    get_provider,
    is_installed,
    load,
    manages,
    manifest_of,
    takes_config,
)

__all__ = [
    "ContainerProvider",
    "Country",
    "Node",
    "countries_for",
    "Provider",
    "ProviderContext",
    "ProviderError",
    "Setting",
    "TunnelProvider",
    "leases_for",
    "check_config",
    "context_for",
    "discover",
    "get_provider",
    "is_installed",
    "load",
    "manages",
    "manifest_of",
    "takes_config",
]


def lease_noun_of(prov) -> str:
    """What the module calls one lease — "node", "server", "port"; "exit" when it
    does not say (an older module)."""
    return getattr(prov, "lease_noun", None) or "exit"


def plural(noun: str, n: int) -> str:
    return noun if n == 1 else f"{noun}s"
