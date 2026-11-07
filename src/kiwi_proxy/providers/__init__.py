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
    Provider,
    ProviderContext,
    ProviderError,
    Setting,
    TunnelProvider,
    countries_for,
    leases_for,
)
from .loader import (
    context_for,
    discover,
    get_provider,
    is_installed,
    load,
    manages,
    manifest_of,
)

__all__ = [
    "ContainerProvider",
    "Country",
    "countries_for",
    "Provider",
    "ProviderContext",
    "ProviderError",
    "Setting",
    "TunnelProvider",
    "leases_for",
    "context_for",
    "discover",
    "get_provider",
    "is_installed",
    "load",
    "manages",
    "manifest_of",
]
