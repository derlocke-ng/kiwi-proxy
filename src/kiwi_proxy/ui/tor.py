"""Where Tor exits may leave, in the app: the Tor preferences page (the Eyes group
no Tor exit uses) and one exit's country and relay lists (Only and Never).

The user's decisions (2026-11-10): one place per scope, the lists follow every
click, the preference's countries are not offered at all, no typed list.
"""

from __future__ import annotations

from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from .. import countries, prefs, providers, selection  # noqa: E402
from . import worker  # noqa: E402
from .help import explain  # noqa: E402

TOR = "tor"


def _counts_and_nodes(module: str = TOR):
    """(exits per country, relays) from the module, {} and [] without it."""
    if not providers.manages(module):
        return {}, []
    prov, manifest = providers.load(module)
    ctx = providers.context_for(module, manifest)
    counts = {}
    get_counts = getattr(prov, "exit_counts", None)
    if get_counts:
        counts = {cc.upper(): n for cc, n in get_counts(ctx).items()}
    nodes = list(getattr(prov, "nodes", lambda _c: [])(ctx))
    if not counts and nodes:
        for n in nodes:
            counts[n.country] = counts.get(n.country, 0) + 1
    return counts, nodes


def _names(codes) -> str:
    return ", ".join(countries.name(c) for c in codes)


# --------------------------------------------------------------- preferences
class TorPage(Adw.PreferencesPage):
    """Preferences → Tor: one choice of four, each with its countries and the
    exits it leaves (mock-up 10)."""

    def __init__(self) -> None:
        super().__init__(title="Tor", icon_name="action-unavailable-symbolic")
        self.group = Adw.PreferencesGroup(
            title="Never exit through", description="For every Tor exit"
        )
        explain(
            self.group,
            "These countries are not in any Tor exit's country and relay lists, and Tor "
            "never leaves through them. More countries are blocked per exit, in its own "
            "list. Most Tor exits are in these countries: fewer exits mean slower circuits "
            "and a smaller crowd to hide in.",
            app="kiwi-proxy",
        )
        self.add(self.group)
        self._rows: dict[str, Adw.ActionRow] = {}
        current = prefs.load().tor_never_group
        first = None
        for key in ("", "five", "nine", "fourteen"):
            row = Adw.ActionRow(title=selection.EYES_TITLES[key], use_markup=False)
            row.set_subtitle_lines(0)
            check = Gtk.CheckButton(valign=Gtk.Align.CENTER)
            if first is None:
                first = check
            else:
                check.set_group(first)
            check.set_active(key == current)
            check.connect("toggled", self._on_toggled, key)
            row.add_prefix(check)
            row.set_activatable_widget(check)
            self.group.add(row)
            self._rows[key] = row
        self._show({})
        worker.run(lambda: _counts_and_nodes()[0], self._show, lambda _e: None)

    def _show(self, counts: dict[str, int]) -> None:
        total = sum(counts.values())
        previous: tuple[str, ...] = ()
        previous_key = ""
        for key, row in self._rows.items():
            group = selection.EYES.get(key, ())
            left = total - sum(counts.get(c, 0) for c in group)
            if not key:
                text = "Tor may use exits in every country"
                if total:
                    text += f" · {total:,} exits"
            else:
                added = [c for c in group if c not in previous]
                lead = f"The {selection.EYES_TITLES[previous_key]} and " if previous else ""
                text = lead + _names(added)
                if total:
                    text += f" · {left:,} exits left"
            row.set_subtitle(text)
            if key:
                previous, previous_key = group, key

    def _on_toggled(self, check, key: str) -> None:
        if not check.get_active():
            return
        p = prefs.load()
        p.tor_never_group = key
        prefs.save(p)


# --------------------------------------------------------------- one exit
class TorExitsDialog(Adw.Dialog):
    """One Tor exit's countries (Only / Never) and relays (mock-ups 11 and 12).
    `on_use(only_countries, only_nodes, never_countries)` gets the lists."""

    LIMIT = 200  # rows of relays at a time; the search narrows the rest

    def __init__(
        self,
        only_countries,
        only_nodes,
        never_countries,
        on_use: Callable[[list[str], list[str], list[str]], None],
        module: str = TOR,
    ) -> None:
        super().__init__(title="Where Tor exits", content_width=720, content_height=760)
        self._on_use = on_use
        self._module = module
        self.only = set(c.upper() for c in only_countries)
        self.never = set(c.upper() for c in never_countries)
        self.nodes_chosen = set(n.upper() for n in only_nodes)
        self.blocked = set(selection.blocked_everywhere())
        self.counts: dict[str, int] = {}
        self.nodes = []
        self._syncing = False

        header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        header.pack_start(cancel)
        use = Gtk.Button(label="Use")
        use.add_css_class("suggested-action")
        use.connect("clicked", self._on_use_clicked)
        header.pack_end(use)
        self.stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        self.country_search = Gtk.SearchEntry(placeholder_text="a country or its code…")
        self.country_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.country_list.add_css_class("boxed-list")
        self.country_list.set_filter_func(self._country_visible)
        self.country_search.connect(
            "search-changed", lambda *_: self.country_list.invalidate_filter()
        )
        self.stack.add_titled_with_icon(
            self._page(self.country_search, self.country_list),
            "countries",
            "Countries",
            "mark-location-symbolic",
        )
        self.node_search = Gtk.SearchEntry(
            placeholder_text="a name, a network, part of a fingerprint…"
        )
        self.node_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.node_list.add_css_class("boxed-list")
        self.node_search.connect("search-changed", lambda *_: self._fill_nodes())
        self.stack.add_titled_with_icon(
            self._page(self.node_search, self.node_list),
            "nodes",
            "Exit nodes",
            "network-server-symbolic",
        )

        self.summary = Gtk.Label(
            wrap=True, xalign=0, margin_start=12, margin_end=12, margin_bottom=10
        )
        self.summary.add_css_class("dim-label")
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(self.stack)
        view.add_bottom_bar(self.summary)
        self.set_child(view)
        self._say()
        worker.run(lambda: _counts_and_nodes(module), self._loaded, self._failed)

    @staticmethod
    def _page(search: Gtk.SearchEntry, listbox: Gtk.ListBox) -> Gtk.Widget:
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=10,
            margin_top=10,
            margin_start=12,
            margin_end=12,
            margin_bottom=10,
        )
        box.append(search)
        scroller = Gtk.ScrolledWindow(vexpand=True, child=listbox)
        box.append(scroller)
        return box

    # ----------------------------------------------------------- loading
    def _loaded(self, result) -> None:
        self.counts, self.nodes = result
        codes = sorted(
            (c for c in set(self.counts) | self.only | self.never if c not in self.blocked),
            key=lambda c: (-self.counts.get(c, 0), countries.name(c)),
        )
        for code in codes:
            self.country_list.append(self._country_row(code))
        self._fill_nodes()
        self._say()

    def _failed(self, exc: Exception) -> None:
        self.summary.set_text(f"The Tor directory is out of reach: {exc}")

    # ---------------------------------------------------------- countries
    def _country_row(self, code: str) -> Adw.ActionRow:
        n = self.counts.get(code)
        row = Adw.ActionRow(title=countries.name(code), use_markup=False)
        row.set_subtitle(f"{code} · {n} exits" if n is not None else code)
        row.code = code  # type: ignore[attr-defined]
        box = Gtk.Box(valign=Gtk.Align.CENTER)
        box.add_css_class("linked")
        only = Gtk.ToggleButton(label="Only", active=code in self.only)
        never = Gtk.ToggleButton(label="Never", active=code in self.never)
        only.connect("toggled", self._on_country, code, "only", never)
        never.connect("toggled", self._on_country, code, "never", only)
        box.append(only)
        box.append(never)
        row.add_suffix(box)
        return row

    def _country_visible(self, row) -> bool:
        text = self.country_search.get_text().strip().lower()
        if not text:
            return True
        code = getattr(row, "code", "")
        return text in code.lower() or text in countries.name(code).lower()

    def _on_country(self, button, code: str, which: str, other) -> None:
        if self._syncing:
            return
        never_before = set(self.never)
        mine, theirs = (self.only, self.never) if which == "only" else (self.never, self.only)
        if button.get_active():
            mine.add(code)
            if code in theirs:
                theirs.discard(code)
                self._syncing = True
                other.set_active(False)
                self._syncing = False
        else:
            mine.discard(code)
        if self.never != never_before:
            self._fill_nodes()  # a Never country's relays leave the list at once
        self._say()

    # -------------------------------------------------------------- nodes
    def _fill_nodes(self) -> None:
        child = self.node_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.node_list.remove(child)
            child = nxt
        text = self.node_search.get_text().strip().lower()
        hidden = self.blocked | self.never
        shown = [
            n
            for n in self.nodes
            if n.country not in hidden
            and (not text or text in f"{n.name} {n.operator} {n.fingerprint} {n.country}".lower())
        ]
        # chosen relays first, then the fastest
        shown.sort(key=lambda n: (n.fingerprint not in self.nodes_chosen, -n.speed))
        for node in shown[: self.LIMIT]:
            self.node_list.append(self._node_row(node))
        if len(shown) > self.LIMIT:
            more = Adw.ActionRow(
                title=f"and {len(shown) - self.LIMIT} more", subtitle="search to narrow the list"
            )
            self.node_list.append(more)
        # a chosen relay in a country now set to Never is dropped with it
        self.nodes_chosen -= {n.fingerprint for n in self.nodes if n.country in hidden}

    def _node_row(self, node) -> Adw.ActionRow:
        fp = node.fingerprint
        short = f"{fp[:4]} {fp[4:8]} … {fp[-4:]}"
        speed = f"{node.speed / 1048576:.0f} MiB/s"
        row = Adw.ActionRow(title=node.name or short, use_markup=False)
        row.set_subtitle(
            " · ".join(
                b
                for b in (
                    f"{node.country} {countries.name(node.country)}",
                    node.operator,
                    speed,
                    short,
                )
                if b
            )
        )
        check = Gtk.CheckButton(active=fp in self.nodes_chosen, valign=Gtk.Align.CENTER)
        check.connect("toggled", self._on_node, fp)
        row.add_prefix(check)
        row.set_activatable_widget(check)
        return row

    def _on_node(self, check, fp: str) -> None:
        if check.get_active():
            self.nodes_chosen.add(fp)
        else:
            self.nodes_chosen.discard(fp)
        self._say()

    # ------------------------------------------------------------ summary
    def _say(self) -> None:
        names = {n.fingerprint: n.name for n in self.nodes}
        only = sorted(self.only) + sorted(names.get(fp, fp[:8]) for fp in self.nodes_chosen)
        bits = [f"Tor leaves only through: {', '.join(only)}." if only else "Tor picks the exits."]
        if self.never:
            bits.append(f"Blocked for this exit: {', '.join(sorted(self.never))}.")
        group = prefs.load().tor_never_group
        if group:
            bits.append(
                f"The {selection.EYES_TITLES[group]} are blocked for every Tor exit (Preferences)."
            )
        self.summary.set_text(" ".join(bits))

    def _on_use_clicked(self, *_args) -> None:
        self._on_use(sorted(self.only), sorted(self.nodes_chosen), sorted(self.never))
        self.close()
