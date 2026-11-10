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
    new_exit_upstream: str = dns.DEFAULT_UPSTREAM
    new_exit_blocklists: list[str] = field(default_factory=lambda: list(dns.DEFAULT_BLOCKLISTS))


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
    p.new_exit_blocklists = [b for b in p.new_exit_blocklists if b in dns.BLOCKLISTS]
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
        mode="resolver", upstream=p.new_exit_upstream, blocklists=list(p.new_exit_blocklists)
    )
