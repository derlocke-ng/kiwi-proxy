"""Provider plugin subsystem.

kiwi-proxy manages SOCKS5/VPN provider modules (tor, vpn, 9proxy, mysterium) that
each expose a ready SOCKS5 upstream for a gateway — and through the gateway for
kiwi-fox, kiwi-pentesting, host applications and kiwi-server machines. Modules are
discovered under paths.modules_dir() and loaded by file path.
"""

from __future__ import annotations

from .base import (
    Account,
    AccountAction,
    ContainerProvider,
    Country,
    HistoryItem,
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
    account_act,
    account_export,
    account_history,
    account_label,
    account_new,
    account_new_settings,
    account_noun,
    account_of,
    account_remove,
    account_rename,
    account_state,
    account_users,
    accounts,
    assigns_leases,
    check_config,
    clean_options,
    config_from,
    config_sources,
    container_of,
    context_for,
    discover,
    exit_options,
    get_provider,
    has_accounts,
    is_installed,
    keys_leases,
    lease_alive,
    lease_key,
    load,
    manages,
    manifest_of,
    takes_config,
)

__all__ = [
    "Account",
    "AccountAction",
    "HistoryItem",
    "account_act",
    "account_export",
    "account_history",
    "account_label",
    "account_new",
    "account_new_settings",
    "account_noun",
    "account_of",
    "account_remove",
    "account_rename",
    "account_users",
    "accounts",
    "has_accounts",
    "keys_leases",
    "lease_key",
    "clean_options",
    "exit_options",
    "account_state",
    "assigns_leases",
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
    "config_from",
    "config_sources",
    "container_of",
    "context_for",
    "discover",
    "get_provider",
    "is_installed",
    "lease_alive",
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
