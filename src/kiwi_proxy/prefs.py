"""Kiwi Proxy's own preferences: what a new exit starts with (the DNS page).

Kept in ``~/.config/kiwi-proxy/prefs.json``; a missing or broken file means the
defaults, which are DnsConfig's own.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from . import dns, paths
from .models import DnsConfig


@dataclass
class Prefs:
    new_exit_upstream: str = dns.DEFAULT_UPSTREAM  # the first of new_exit_upstreams
    # The DNS services a new exit asks (the fastest that answers).
    new_exit_upstreams: list[str] = field(default_factory=lambda: list(dns.SERVICE_ORDER))
    new_exit_blocklists: list[str] = field(default_factory=lambda: list(dns.DEFAULT_BLOCKLISTS))
    # Countries no Tor exit ever leaves through: "" (none), "five", "nine",
    # "fourteen" (the Eyes groups, kiwi_proxy.selection.EYES).
    tor_never_group: str = ""
    # The group also as entry (guard) and middle relays, not only as the exit.
    tor_never_all: bool = False


def path():
    return paths.config_dir() / "prefs.json"


def load() -> Prefs:
    try:
        data = json.loads(path().read_text())
        p = Prefs(**{k: v for k, v in data.items() if k in Prefs.__dataclass_fields__})
    except (OSError, ValueError, TypeError):
        return Prefs()
    if p.new_exit_upstream not in dns.UPSTREAMS:
        p.new_exit_upstream = dns.DEFAULT_UPSTREAM
    if "new_exit_upstreams" not in data and p.new_exit_upstream != dns.DEFAULT_UPSTREAM:
        # Chosen before there were several: that one stays the choice.
        p.new_exit_upstreams = [p.new_exit_upstream]
    p.new_exit_upstreams = dns.clean_services(p.new_exit_upstreams) or list(dns.SERVICE_ORDER)
    p.new_exit_upstream = p.new_exit_upstreams[0]
    p.new_exit_blocklists = [b for b in p.new_exit_blocklists if b in dns.BLOCKLISTS]
    if p.tor_never_group not in ("", "five", "nine", "fourteen"):
        p.tor_never_group = ""
    return p


def save(p: Prefs) -> None:
    target = path()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(p), indent=2) + "\n")
    tmp.replace(target)


def new_exit_dns() -> DnsConfig:
    """What a new exit starts with; each exit is changed in its own editor."""
    p = load()
    return DnsConfig(
        mode="resolver",
        upstream=p.new_exit_upstreams[0],
        upstreams=list(p.new_exit_upstreams),
        blocklists=list(p.new_exit_blocklists),
    )
