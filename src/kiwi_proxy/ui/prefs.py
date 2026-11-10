"""Kiwi Proxy's preference pages besides Snapshots: DNS (what a new exit starts
with). Tor comes with step 6."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

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
            "gateway and asks the chosen DNS-over-HTTPS service through the exit; the "
            "blocklist refuses ad, tracker and malware names for everything on the exit.",
            app="kiwi-proxy",
            anchor="dns",
        )
        self._upstreams = list(dns.UPSTREAMS)
        self.upstream_row = Adw.ComboRow(
            title="Resolve names through",
            model=Gtk.StringList.new([UPSTREAM_LABELS.get(u, u.title()) for u in self._upstreams]),
        )
        self.upstream_row.set_selected(self._upstreams.index(p.new_exit_upstream))
        self.upstream_row.connect("notify::selected", self._on_upstream)
        group.add(self.upstream_row)
        self.block_row = Adw.SwitchRow(title="Block ads and trackers")
        self.block_row.set_active(bool(p.new_exit_blocklists))
        self._show_lists(p.new_exit_blocklists or dns.DEFAULT_BLOCKLISTS)
        self.block_row.connect("notify::active", self._on_block)
        group.add(self.block_row)
        self.add(group)

    def _show_lists(self, lists: list[str]) -> None:
        self.block_row.set_subtitle(", ".join(n.replace("-", " ") for n in lists))

    def _on_upstream(self, row, _param) -> None:
        p = prefs.load()
        p.new_exit_upstream = self._upstreams[row.get_selected()]
        prefs.save(p)

    def _on_block(self, row, _param) -> None:
        p = prefs.load()
        p.new_exit_blocklists = list(dns.DEFAULT_BLOCKLISTS) if row.get_active() else []
        prefs.save(p)
        self._show_lists(p.new_exit_blocklists or dns.DEFAULT_BLOCKLISTS)
