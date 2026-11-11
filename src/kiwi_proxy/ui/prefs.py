"""Kiwi Proxy's preference pages besides Snapshots: DNS (what a new exit starts
with). Tor comes with step 6."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from .. import dns, prefs  # noqa: E402
from .help import explain  # noqa: E402

UPSTREAM_LABELS = {
    "quad9": "Quad9",
    "cloudflare": "Cloudflare",
    "mullvad": "Mullvad",
    "google": "Google",
}


class DnsPage(Adw.PreferencesPage):
    def __init__(self) -> None:
        super().__init__(title="DNS", icon_name="network-server-symbolic")
        p = prefs.load()
        group = Adw.PreferencesGroup(title="New exits", description="What a new exit starts with")
        explain(
            group,
            "Each exit can be changed in its editor. The resolver runs in the exit's "
            "gateway and asks the chosen DNS-over-HTTPS services through the exit, the "
            "fastest that answers; the blocklist refuses ad, tracker and malware names "
            "for everything on the exit.",
            app="kiwi-proxy",
            anchor="dns",
        )
        self.block_row = Adw.SwitchRow(title="Block ads and trackers")
        self.block_row.set_active(bool(p.new_exit_blocklists))
        self._show_lists(p.new_exit_blocklists or dns.DEFAULT_BLOCKLISTS)
        self.block_row.connect("notify::active", self._on_block)
        group.add(self.block_row)
        self.add(group)
        services = Adw.PreferencesGroup(
            title="DNS services", description="the fastest that answers"
        )
        self.service_rows: dict[str, Adw.SwitchRow] = {}
        for name in dns.SERVICE_ORDER:
            row = Adw.SwitchRow(title=UPSTREAM_LABELS.get(name, name.title()))
            row.set_active(name in p.new_exit_upstreams)
            row.connect("notify::active", self._on_service)
            services.add(row)
            self.service_rows[name] = row
        self.add(services)

    def _show_lists(self, lists: list[str]) -> None:
        self.block_row.set_subtitle(", ".join(n.replace("-", " ") for n in lists))

    def _on_service(self, row, _param) -> None:
        chosen = [n for n, r in self.service_rows.items() if r.get_active()]
        if not chosen:  # at least one: the switch just turned off goes back on
            row.set_active(True)
            return
        p = prefs.load()
        p.new_exit_upstreams, p.new_exit_upstream = chosen, chosen[0]
        prefs.save(p)

    def _on_block(self, row, _param) -> None:
        p = prefs.load()
        p.new_exit_blocklists = list(dns.DEFAULT_BLOCKLISTS) if row.get_active() else []
        prefs.save(p)
        self._show_lists(p.new_exit_blocklists or dns.DEFAULT_BLOCKLISTS)
