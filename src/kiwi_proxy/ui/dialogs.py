"""Dialogs: add or edit an exit, show what an exit is, and the provider modules."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from .. import dns, endpoint, exits, gateway, paths, podman, providers, secrets  # noqa: E402
from ..models import DnsConfig, Lease  # noqa: E402
from . import worker  # noqa: E402

DNS_MODES = (
    ("resolver", "Resolved in the gateway"),
    ("remote", "Resolved by the exit"),
)
SOCKS_AUTH = (
    ("inject", "Add the exit's credentials (default)"),
    ("passthrough", "Pass a client's own through (Tor Browser)"),
)
BLOCKLIST_LABELS = {
    "oisd-big": ("Ads, trackers, malware", "oisd big — the full list"),
    "oisd-small": ("Ads and trackers, lighter", "oisd small — fewer false positives"),
    "oisd-nsfw": ("Adult content", "oisd nsfw"),
}
SOCKS5 = "SOCKS5 endpoint"
ANY_COUNTRY = "Any country"
ANY_LEASE = "(the provider's choice)"
FIRST_HOST_PORT = 1081


def proxy_url(ex) -> str:
    """What to paste into an application: socks5h, so names go to the exit too."""
    user = f"{ex.expose.username}@" if ex.expose and ex.expose.username else ""
    return f"socks5h://{user}{ex.expose.address}" if ex.expose else ""


def endpoint_text(ep) -> str:
    """The endpoint as the editor shows it: never with its password."""
    user = f"{ep.username}@" if ep.username else ""
    return f"socks5://{user}{ep.host}:{ep.port}"


def next_host_port() -> int:
    taken = {e.expose.port for e in exits.list_exits() if e.expose}
    port = FIRST_HOST_PORT
    while port in taken:
        port += 1
    return port


def _combo(title: str, labels: list[str], selected: int = 0, subtitle: str = "") -> Adw.ComboRow:
    row = Adw.ComboRow(title=title, subtitle=subtitle)
    row.set_model(Gtk.StringList.new(labels))
    row.set_selected(selected)
    return row


def _row(title: str, subtitle: str, *, copy: str | None = None, toast=None) -> Adw.ActionRow:
    row = Adw.ActionRow(use_markup=False, title=title, subtitle=subtitle or "—")
    row.add_css_class("property")
    if copy:
        button = Gtk.Button(
            icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copy"
        )
        button.add_css_class("flat")

        def on_copy(*_a) -> None:
            Gdk.Display.get_default().get_clipboard().set(copy)
            if toast:
                toast(f"Copied {copy}")

        button.connect("clicked", on_copy)
        row.add_suffix(button)
    return row


def _dialog_header(primary: str, on_primary) -> tuple[Adw.HeaderBar, Gtk.Button, Gtk.Button]:
    header = Adw.HeaderBar(show_end_title_buttons=False, show_start_title_buttons=False)
    cancel = Gtk.Button(label="Cancel")
    header.pack_start(cancel)
    button = Gtk.Button(label=primary)
    button.add_css_class("suggested-action")
    button.connect("clicked", on_primary)
    header.pack_end(button)
    return header, cancel, button


class ExitEditor(Adw.Dialog):
    """Add an exit (`ex` None) or change one. Everything is checked the way the CLI
    checks it (exits.make_expose, endpoint.parse) before anything is saved.
    `template` fills a new exit from an existing one (Duplicate); passwords are
    not copied."""

    def __init__(self, ex, on_saved, *, template=None) -> None:
        super().__init__(
            title="New exit" if ex is None else f"Edit {ex.name}",
            content_width=600,
            content_height=720,
        )
        self.ex = ex
        self._on_saved = on_saved
        self._modules = providers.discover()
        self._leases: list[str | None] = [None]

        page = Adw.PreferencesPage()

        # ------------------------------------------------------------ upstream
        upstream = Adw.PreferencesGroup(
            title="Upstream",
            description="Where the traffic leaves: a SOCKS5 you were given, or one a "
            "provider module produces.",
        )
        self.name_row = Adw.EntryRow(title="Name")
        upstream.add(self.name_row)
        self.source_row = _combo("Source", [SOCKS5, *self._modules])
        self.source_row.connect("notify::selected", self._on_source)
        upstream.add(self.source_row)
        self.endpoint_row = Adw.EntryRow(title="Endpoint (socks5://user:pass@host:port)")
        upstream.add(self.endpoint_row)
        # The module's exit — a Mysterium provider, a gluetun server — chosen in a
        # picker that lists every one with search and filters (LeasePicker).
        self._lease: str | None = None
        self.lease_row = Adw.ActionRow(title="Exit", subtitle=ANY_LEASE, use_markup=False)
        self.lease_row.set_subtitle_lines(0)
        self.lease_button = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
        self.lease_button.connect("clicked", self._on_choose_lease)
        self.lease_row.add_suffix(self.lease_button)
        self.lease_row.set_activatable_widget(self.lease_button)
        upstream.add(self.lease_row)
        # The module says where it can exit (Tor relays, Mysterium providers, with
        # counts); a module that cannot say gets every country there is.
        self.country_row = Adw.ComboRow(title="Country", subtitle="any", enable_search=True)
        self._countries: list[str | None] = [None]
        self.country_row.set_model(Gtk.StringList.new([ANY_COUNTRY]))
        self.country_row.connect("notify::selected", self._on_country)
        upstream.add(self.country_row)
        self.test_row = Adw.ActionRow(
            title="Test the upstream", subtitle="ask what the world sees through it"
        )
        self.test_button = Gtk.Button(label="Test", valign=Gtk.Align.CENTER)
        self.test_button.connect("clicked", self._on_test)
        self.test_row.add_suffix(self.test_button)
        upstream.add(self.test_row)
        page.add(upstream)

        # ---------------------------------------------------------------- host
        host = Adw.PreferencesGroup(
            title="On this computer",
            description="Offer the exit as a SOCKS5 port, for a browser or any other "
            "application here. Its traffic still leaves only through the exit.",
        )
        self.expose_row = Adw.SwitchRow(title="Offer a SOCKS5 port")
        self.expose_row.connect("notify::active", self._refresh)
        host.add(self.expose_row)
        self.bind_row = Adw.EntryRow(title="Address")
        self.bind_row.set_text("127.0.0.1")
        self.bind_row.connect("changed", self._refresh)
        host.add(self.bind_row)
        self.port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        self.port_row.set_title("Port")
        self.port_row.set_value(next_host_port())
        host.add(self.port_row)
        self.auth_row = Adw.SwitchRow(title="Require a password")
        self.auth_row.connect("notify::active", self._refresh)
        host.add(self.auth_row)
        self.user_row = Adw.EntryRow(title="User")
        host.add(self.user_row)
        self.password_row = Adw.PasswordEntryRow(title="Password")
        host.add(self.password_row)
        self.open_row = Adw.SwitchRow(
            title="Open to other machines without a password",
            subtitle="anyone who can reach this address can use the exit",
        )
        host.add(self.open_row)
        page.add(host)

        # ----------------------------------------------------------------- dns
        dns_group = Adw.PreferencesGroup(
            title="DNS and ad-blocking",
            description="The resolver asks its upstream through the exit too. Names on "
            "the lists are refused — for containers that join the exit and for "
            "socks5h on the SOCKS5 port alike.",
        )
        self.dns_row = _combo(
            "Names",
            [label for _k, label in DNS_MODES],
            subtitle="by the exit, as Tor needs (.onion resolves only there); listed names are still refused",
        )
        self.dns_row.connect("notify::selected", self._refresh)
        dns_group.add(self.dns_row)
        self._upstreams = sorted(dns.UPSTREAMS)
        self.upstream_row = _combo(
            "Resolver upstream", self._upstreams, self._upstreams.index(DnsConfig().upstream)
        )
        dns_group.add(self.upstream_row)
        self.list_rows: dict[str, Adw.SwitchRow] = {}
        for name in dns.BLOCKLISTS:
            title, subtitle = BLOCKLIST_LABELS.get(name, (name, ""))
            row = Adw.SwitchRow(title=title, subtitle=subtitle)
            row.set_active(name in DnsConfig().blocklists)
            dns_group.add(row)
            self.list_rows[name] = row
        page.add(dns_group)

        advanced = Adw.PreferencesGroup(title="Advanced")
        self.socks_row = _combo(
            "Client credentials",
            [label for _k, label in SOCKS_AUTH],
            subtitle="Tor Browser keeps a circuit per site only when they pass through",
        )
        advanced.add(self.socks_row)
        page.add(advanced)

        self.status = Adw.PreferencesGroup()
        self.status_label = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.status_label.add_css_class("error")
        self.status.add(self.status_label)
        page.add(self.status)

        header, cancel, self.save_button = _dialog_header(
            "Add" if ex is None else "Save", self._on_save
        )
        cancel.connect("clicked", lambda *_: self.close())

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(page)
        self.set_child(view)

        if ex is not None:
            self._load(ex)
        elif template is not None:
            self._load(template)
            self.name_row.set_text(f"{template.name}-2")
            self.port_row.set_value(next_host_port())
            self.password_row.set_title("Password")
            if template.endpoint.has_password or (template.expose and template.expose.username):
                self._say("Passwords are not copied: type them again.", error=False)
        self._on_source()

    # ------------------------------------------------------------- the form
    @property
    def module(self) -> str | None:
        i = self.source_row.get_selected()
        return self._modules[i - 1] if i > 0 else None

    def _load(self, ex) -> None:
        self.name_row.set_text(ex.name)
        if ex.endpoint.module in self._modules:
            self.source_row.set_selected(1 + self._modules.index(ex.endpoint.module))
            self._set_lease(ex.endpoint.lease)
        else:
            self.endpoint_row.set_text(endpoint_text(ex.endpoint))
        self._want_country = (ex.endpoint.country or "").upper() or None
        self._select_country(self._want_country)
        if ex.expose:
            self.expose_row.set_active(True)
            self.bind_row.set_text(ex.expose.bind)
            self.port_row.set_value(ex.expose.port)
            if ex.expose.username:
                self.auth_row.set_active(True)
                self.user_row.set_text(ex.expose.username)
                self.password_row.set_title("Password (empty: keep the stored one)")
            elif not ex.expose.loopback:
                self.open_row.set_active(True)
        self.dns_row.set_selected([k for k, _l in DNS_MODES].index(ex.dns.mode))
        for name, row in self.list_rows.items():
            row.set_active(name in ex.dns.blocklists)
        if ex.dns.upstream in self._upstreams:
            self.upstream_row.set_selected(self._upstreams.index(ex.dns.upstream))
        self.socks_row.set_selected([k for k, _l in SOCKS_AUTH].index(ex.socks_auth))

    def _on_source(self, *_args) -> None:
        module = self.module
        self.endpoint_row.set_visible(module is None)
        self.lease_row.set_visible(module is not None)
        self.country_row.set_visible(module is not None)
        # Another module's exit means nothing here; the edited exit's own is kept.
        own = self.ex.endpoint.lease if self.ex and self.ex.endpoint.module == module else None
        if self._lease != own:
            self._set_lease(own)
        self._load_countries()
        self._refresh()

    @property
    def country(self) -> str | None:
        """The chosen country code, or None for any."""
        index = self.country_row.get_selected()
        return self._countries[index] if 0 <= index < len(self._countries) else None

    def _select_country(self, code: str | None) -> None:
        self.country_row.set_selected(self._countries.index(code) if code in self._countries else 0)

    def _load_countries(self) -> None:
        """The module's countries, off the main thread (Tor asks its directory,
        Mysterium its discovery service); the choice made so far is kept."""
        module = self.module
        if not module:
            return
        generation = self._country_generation = getattr(self, "_country_generation", 0) + 1

        def work():
            prov, manifest = providers.load(module)
            return providers.countries_for(prov, ctx := providers.context_for(module, manifest)), (
                bool(getattr(prov, "countries", lambda _c: [])(ctx))
            )

        def done(result) -> None:
            if generation != self._country_generation or self.module != module:
                return
            found, own = result
            # Keep the country chosen so far, or the edited exit's — read now, not
            # when the module was asked: _load sets the exit's after the source.
            want = self.country or getattr(self, "_want_country", None)
            self._countries = [None, *(c.code.upper() for c in found)]
            self.country_row.set_model(Gtk.StringList.new([ANY_COUNTRY, *(c.label for c in found)]))
            self._select_country(want.upper() if want else None)
            self.country_row.set_subtitle(
                f"{len(found)} the module has exits in" if own else "any — the module does not say"
            )

        def failed(exc: Exception) -> None:
            if generation == self._country_generation:
                self.country_row.set_subtitle(f"module: {exc}")

        worker.run(work, done, failed)

    def _on_country(self, *_args) -> None:
        pass  # the picker asks the module for the country chosen when it opens

    def _set_lease(self, lease_id: str | None, lease: Lease | None = None) -> None:
        """What the picker chose (or the edited exit has): the id kept for the
        endpoint, and the row says which it is."""
        self._lease = lease_id or None
        if not lease_id:
            self.lease_row.set_subtitle(ANY_LEASE)
        elif lease is None:
            self.lease_row.set_subtitle(Lease(id=lease_id).short_id)
        else:
            self.lease_row.set_subtitle(lease_line(lease))

    def _on_choose_lease(self, *_args) -> None:
        if self.module:
            LeasePicker(self.module, self.country, self._lease, self._set_lease).present(self)

    def _refresh(self, *_args) -> None:
        exposed = self.expose_row.get_active()
        for row in (self.bind_row, self.port_row, self.auth_row):
            row.set_visible(exposed)
        authed = exposed and self.auth_row.get_active()
        self.user_row.set_visible(authed)
        self.password_row.set_visible(authed)
        bind = self.bind_row.get_text().strip() or "127.0.0.1"
        loopback = bind in ("127.0.0.1", "::1", "localhost") or bind.startswith("127.")
        self.open_row.set_visible(exposed and not authed and not loopback)
        # Only the resolver has an upstream; the lists apply in both modes (the
        # forwarder refuses listed names a remote-DNS client hands it).
        resolver = DNS_MODES[self.dns_row.get_selected()][0] == "resolver"
        self.upstream_row.set_visible(resolver)
        self.test_row.set_visible(self.module is None)

    def _say(self, text: str, *, error: bool = True) -> None:
        self.status_label.set_text(text)
        self.status_label.set_visible(bool(text))
        (self.status_label.add_css_class if error else self.status_label.remove_css_class)("error")

    def collect(self) -> dict:
        """The form as the arguments of an exit, or ValueError saying what is wrong.
        Kept free of side effects so it can be tested without a display server."""
        name = self.name_row.get_text().strip()
        if not exits.valid_name(name):
            raise ValueError("give the exit a name (no slash, not starting with -)")
        password = None
        module = self.module
        if module:
            country = self.country.lower() if self.country else None
            ep = exits.module_endpoint(module, lease=self._lease, country=country)
        else:
            text = self.endpoint_row.get_text().strip()
            if (
                self.ex is not None
                and not self.ex.endpoint.module
                and text == endpoint_text(self.ex.endpoint)
            ):
                ep = self.ex.endpoint  # unchanged: keep it, and its stored password
            else:
                try:
                    ep, password = endpoint.parse(text)
                except endpoint.EndpointError as exc:
                    raise ValueError(str(exc)) from exc
        expose, expose_password = None, None
        if self.expose_row.get_active():
            user = self.user_row.get_text().strip() if self.auth_row.get_active() else None
            expose_password = self.password_row.get_text() if user else None
            kept = (
                self.ex is not None
                and self.ex.expose is not None
                and self.ex.expose.username == user
                and self.ex.expose.has_password
            )
            expose = exits.make_expose(
                self.bind_row.get_text().strip() or "127.0.0.1",
                int(self.port_row.get_value()),
                username=user,
                password=expose_password or ("kept" if user and kept else None),
                allow_open=self.open_row.get_active(),
            )
            for other in exits.list_exits():
                if (
                    other.expose
                    and other.expose.port == expose.port
                    and (not self.ex or other.id != self.ex.id)
                ):
                    raise ValueError(f"port {expose.port} is already {other.name}'s")
        dns_cfg = DnsConfig(
            mode=DNS_MODES[self.dns_row.get_selected()][0],
            upstream=self._upstreams[self.upstream_row.get_selected()],
            blocklists=[n for n, row in self.list_rows.items() if row.get_active()],
        )
        return {
            "name": name,
            "endpoint": ep,
            "password": password,
            "expose": expose,
            "expose_password": expose_password or None,
            "dns": dns_cfg,
            "socks_auth": SOCKS_AUTH[self.socks_row.get_selected()][0],
        }

    def _on_test(self, *_args) -> None:
        """Probe a plain endpoint from here, the way kiwi-fox probes before it
        creates a profile. A module's exit only exists once it is up."""
        text = self.endpoint_row.get_text().strip()
        try:
            ep, password = endpoint.parse(text)
        except endpoint.EndpointError as exc:
            self.test_row.set_subtitle(str(exc))
            return
        if password is None and self.ex is not None and text == endpoint_text(self.ex.endpoint):
            password = secrets.lookup(self.ex.id)
        self.test_button.set_sensitive(False)
        self.test_row.set_subtitle("asking…")

        def done(info) -> None:
            self.test_button.set_sensitive(True)
            where = " ".join(x for x in (info.country, info.city, info.asn) if x)
            self.test_row.set_subtitle(f"{info.ip} {where}".rstrip())

        def failed(exc: Exception) -> None:
            self.test_button.set_sensitive(True)
            self.test_row.set_subtitle(f"no answer: {exc}")

        worker.run(lambda: endpoint.preflight(ep, password), done, failed)

    def _on_save(self, *_args) -> None:
        try:
            form = self.collect()
        except (ValueError, providers.ProviderError) as exc:
            self._say(str(exc))
            return
        self._say("")
        ex = self.ex

        def work():
            if ex is None:
                created = exits.create(
                    form["name"],
                    form["endpoint"],
                    password=form["password"],
                    dns=form["dns"],
                    expose=form["expose"],
                    expose_password=form["expose_password"],
                )
                created.socks_auth = form["socks_auth"]
                exits.save(created)
                return created
            if form["name"] != ex.name and exits.find_by_name(form["name"]):
                raise exits.ExitError(f"an exit named {form['name']!r} already exists")
            if form["endpoint"] is not ex.endpoint:
                secrets.clear(ex.id, kind="endpoint")
                if form["password"]:
                    secrets.store(ex.id, form["password"], kind="endpoint")
            if form["expose"] is None or not form["expose"].username:
                secrets.clear(ex.id, kind="expose")
            elif form["expose_password"]:
                secrets.store(ex.id, form["expose_password"], kind="expose")
            ex.name, ex.endpoint, ex.dns = form["name"], form["endpoint"], form["dns"]
            ex.expose, ex.socks_auth = form["expose"], form["socks_auth"]
            exits.save(ex)
            return ex

        def done(saved) -> None:
            self.close()
            self._on_saved(saved)

        worker.run(work, done, lambda exc: self._say(str(exc)))


class ExitDetails(Adw.Dialog):
    """Everything about one exit, and who is inside its gateway right now."""

    def __init__(self, ex, on_changed=None, toast=None) -> None:
        super().__init__(title=ex.name, content_width=560, content_height=640)
        self.ex = ex
        self._on_changed = on_changed
        self._toast = toast
        name = paths.gateway_name(ex.id)

        page = Adw.PreferencesPage()
        state = Adw.PreferencesGroup(title="Gateway")
        self.state_row = _row("State", "checking…")
        state.add(self.state_row)
        state.add(_row("Container", name, copy=name, toast=toast))
        state.add(
            _row(
                "Join it with", f"--network container:{name}", copy=f"container:{name}", toast=toast
            )
        )
        self.members_row = _row("Members", "—")
        state.add(self.members_row)
        page.add(state)

        up = Adw.PreferencesGroup(title="Upstream")
        up.add(
            _row(
                "Endpoint",
                ex.endpoint.label
                + (f" (user {ex.endpoint.username})" if ex.endpoint.username else ""),
            )
        )
        if ex.endpoint.module:
            up.add(
                _row(
                    "Provider",
                    f"{ex.endpoint.module} · lease {ex.endpoint.lease or 'default'} · country {ex.endpoint.country or 'any'}",
                )
            )
        if ex.last_exit:
            e = ex.last_exit
            up.add(
                _row(
                    "Last seen exit",
                    f"{e.ip} · {e.country or '?'} {e.city or ''} · {e.seen:%Y-%m-%d %H:%M}",
                )
            )
        up.add(
            _row(
                "DNS",
                dict(DNS_MODES)[ex.dns.mode]
                + (f" · {ex.dns.upstream}" if ex.dns.mode == "resolver" else ""),
            )
        )
        lists = ", ".join(BLOCKLIST_LABELS.get(n, (n,))[0].lower() for n in ex.dns.blocklists)
        up.add(_row("Ad-blocking", lists or "off"))
        up.add(_row("Client credentials", dict(SOCKS_AUTH)[ex.socks_auth]))
        page.add(up)

        if ex.expose:
            host = Adw.PreferencesGroup(title="On this computer")
            url = proxy_url(ex)
            host.add(_row("Proxy", url, copy=url, toast=toast))
            host.add(_row("Password", "required" if ex.expose.username else "none"))
            page.add(host)

        about = Adw.PreferencesGroup(title="Exit")
        about.add(_row("Id", ex.id, copy=ex.id, toast=toast))
        if ex.owner:
            about.add(_row("Made by", ex.owner))
        if ex.notes:
            about.add(_row("Notes", ex.notes))
        page.add(about)

        header = Adw.HeaderBar()
        edit = Gtk.Button(label="Edit…")
        edit.connect("clicked", self._on_edit)
        header.pack_start(edit)
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(page)
        self.set_child(view)
        self._load_state(name)

    def _load_state(self, name: str) -> None:
        def work():
            if not podman.available():
                return False, []
            running = podman.is_running(name)
            return running, podman.dependents(name) if running else []

        def done(result) -> None:
            running, members = result
            held = " · kept up until taken down" if gateway.held(self.ex.id) else ""
            self.state_row.set_subtitle(("up" if running else "down") + held)
            self.members_row.set_subtitle(", ".join(members) or "none")

        worker.run(work, done)

    def _on_edit(self, *_args) -> None:
        def saved(ex) -> None:
            self.close()
            if self._on_changed:
                self._on_changed(ex)

        ExitEditor(self.ex, saved).present(self)


def lease_line(lease: Lease) -> str:
    """One line for a lease: short id, place, kind and what the module adds."""
    place = lease.city or lease.country
    return " · ".join(x for x in (lease.short_id, place, lease.kind, lease.detail, lease.isp) if x)


class LeasePicker(Adw.Dialog):
    """Choose a module's exit — a Mysterium provider, a gluetun server — the way
    Mysterium's own app does: every one the module offers for the country, best
    first, with a search box (any part of an id, a city, an ISP), one toggle per
    IP type, and a field to force an id the list does not show. `on_picked(id,
    lease)` gets the choice; None for the module's own."""

    def __init__(self, module: str, country: str | None, current: str | None, on_picked) -> None:
        self.module, self.country, self.current = module, country, current
        self._on_picked = on_picked
        self._leases: list[Lease] = []
        self._kind: str | None = None
        self.rows: list[Adw.ActionRow] = []
        where = f" in {country.upper()}" if country else ""
        super().__init__(
            title=f"Exit through {module}{where}", content_width=720, content_height=780
        )
        header, cancel, self.use_button = _dialog_header("Use", self._on_use)
        cancel.connect("clicked", lambda *_: self.close())

        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=8,
            margin_top=12,
            margin_bottom=12,
            margin_start=12,
            margin_end=12,
        )
        self.search = Gtk.SearchEntry(placeholder_text="any part of an id, a city, an ISP…")
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        box.append(self.search)
        self.kinds = Gtk.Box(spacing=6)
        box.append(self.kinds)
        self.status = Gtk.Label(label="asking the module…", xalign=0, wrap=True)
        self.status.add_css_class("dim-label")
        box.append(self.status)

        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.set_filter_func(self._filter)
        self.listbox.connect("row-activated", lambda _lb, row: self._pick(row.lease_id))
        any_row = Adw.ActionRow(use_markup=False)
        any_row.set_title(ANY_LEASE)
        any_row.set_subtitle("the module picks")
        any_row.lease_id, any_row.lease = None, None
        self.listbox.append(any_row)
        if current is None:
            self.listbox.select_row(any_row)
        box.append(Gtk.ScrolledWindow(vexpand=True, child=self.listbox))

        force = Adw.PreferencesGroup()
        self.id_row = Adw.EntryRow(title="Or an id to force — one the list does not show")
        if current and current not in [x.id for x in self._leases]:
            self.id_row.set_text(current)
        use_id = Gtk.Button(label="Use this id", valign=Gtk.Align.CENTER)
        use_id.connect("clicked", lambda *_: self._pick(self.id_row.get_text().strip()))
        self.id_row.add_suffix(use_id)
        force.add(self.id_row)
        box.append(force)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(box)
        self.set_child(view)
        self._load()

    # ------------------------------------------------------------------ data
    def _load(self) -> None:
        module, country = self.module, self.country

        def work():
            prov, manifest = providers.load(module)
            ctx = providers.context_for(module, manifest)
            return manifest, providers.leases_for(prov, ctx, country)

        def done(result) -> None:
            manifest, leases = result
            self._leases = sorted(leases, key=lambda x: -(x.quality or 0))
            for lease in self._leases:
                row = self._row_for(lease)
                self.rows.append(row)
                self.listbox.append(row)
                if lease.id == self.current:
                    self.listbox.select_row(row)
                    self.id_row.set_text("")
            self._build_kinds()
            n = len(self._leases)
            where = f" in {country.upper()}" if country else ""
            self.status.set_text(
                f"{n} to choose from{where}, best first"
                if n
                else f"{manifest.title} offers nothing to choose{where}; "
                "the module's choice, or an id typed below"
            )

        def failed(exc: Exception) -> None:
            self.status.set_text(f"module: {exc} — an id can still be typed below")

        worker.run(work, done, failed)

    def _row_for(self, lease: Lease) -> Adw.ActionRow:
        place = lease.city or lease.country or ""
        # Plain text, set after use_markup is off (construction order is not
        # guaranteed): ISPs are "1&1", "GmbH & Co. KG".
        row = Adw.ActionRow(use_markup=False, tooltip_text=lease.id)
        row.set_title(f"{lease.short_id}   {place}".rstrip())
        row.set_subtitle(" · ".join(x for x in (lease.kind, lease.detail, lease.isp) if x))
        row.set_subtitle_lines(0)
        row.lease_id, row.lease = lease.id, lease
        return row

    def _build_kinds(self) -> None:
        counts: dict[str, int] = {}
        for lease in self._leases:
            if lease.kind:
                counts[lease.kind] = counts.get(lease.kind, 0) + 1
        if not counts:
            return
        first = Gtk.ToggleButton(label=f"All ({len(self._leases)})", active=True)
        first.connect("toggled", self._on_kind, None)
        self.kinds.append(first)
        for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            button = Gtk.ToggleButton(label=f"{kind} ({n})", group=first)
            button.connect("toggled", self._on_kind, kind)
            self.kinds.append(button)

    # ---------------------------------------------------------------- filter
    def _on_kind(self, button, kind: str | None) -> None:
        if button.get_active():
            self._kind = kind
            self.listbox.invalidate_filter()

    def _filter(self, row) -> bool:
        lease = getattr(row, "lease", None)
        if lease is None:
            return True  # the module's own choice is always there
        return (self._kind is None or lease.kind == self._kind) and lease.matches(
            self.search.get_text()
        )

    # ---------------------------------------------------------------- choice
    def _on_use(self, *_args) -> None:
        forced = self.id_row.get_text().strip()
        row = self.listbox.get_selected_row()
        if forced and (row is None or row.lease_id is None):
            self._pick(forced)
        elif row is not None:
            self._pick(row.lease_id)

    def _pick(self, lease_id: str | None) -> None:
        lease = next((x for x in self._leases if x.id == lease_id), None)
        self._on_picked(lease_id or None, lease)
        if self.get_mapped():
            self.close()


class ModuleConfigDialog(Adw.Dialog):
    """What a module needs from the user — the settings it declares — as a form: a
    file is chosen, a password is typed unechoed, text is typed. Apply hands the
    values to the module's ``configure`` and shows what it says."""

    def __init__(self, name: str, on_done=None) -> None:
        self.name = name
        self.prov, self.manifest = providers.load(name)
        self.ctx = providers.context_for(name, self.manifest)
        super().__init__(
            title=f"Configure {self.manifest.title}", content_width=560, content_height=460
        )
        self._on_done = on_done
        self._files: dict[str, str] = {}
        self.rows: dict[str, Gtk.Widget] = {}
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(description=self.manifest.notes or self.manifest.description)
        for st in self.prov.settings(self.ctx):
            title = st.title + ("" if st.required else " (optional)")
            if st.kind == "file":
                row = Adw.ActionRow(title=title, subtitle=st.help or "no file chosen")
                row.set_subtitle_lines(0)
                choose = Gtk.Button(label="Choose…", valign=Gtk.Align.CENTER)
                choose.connect("clicked", self._on_choose, st.key, row)
                row.add_suffix(choose)
            elif st.kind == "password":
                row = Adw.PasswordEntryRow(title=title)
            else:
                row = Adw.EntryRow(title=title)
            group.add(row)
            if st.kind != "file" and st.help:
                note = Adw.ActionRow(subtitle=st.help, use_markup=False)
                note.set_subtitle_lines(0)
                group.add(note)
            self.rows[st.key] = row
        page.add(group)

        self.state_row = _row("Now", self.prov.configured(self.ctx) or "not configured")
        state = Adw.PreferencesGroup()
        state.add(self.state_row)
        page.add(state)
        status = Adw.PreferencesGroup()
        self.status_label = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.status_label.add_css_class("dim-label")
        status.add(self.status_label)
        page.add(status)

        header, cancel, self.apply_button = _dialog_header("Apply", self._on_apply)
        cancel.connect("clicked", lambda *_: self.close())
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(page)
        self.set_child(view)

    def _on_choose(self, _button, key: str, row: Adw.ActionRow) -> None:
        dialog = Gtk.FileDialog(title=row.get_title())

        def picked(d, result) -> None:
            try:
                file = d.open_finish(result)
            except GLib.Error:
                return  # cancelled
            if file is not None and file.get_path():
                self._files[key] = file.get_path()
                row.set_subtitle(file.get_path())

        dialog.open(self.get_root(), None, picked)

    def collect(self) -> dict[str, str]:
        """The values as typed and chosen, or ValueError naming what is missing.
        Side-effect free, so it can be tested without a display server."""
        values: dict[str, str] = {}
        for st in self.prov.settings(self.ctx):
            if st.kind == "file":
                value = self._files.get(st.key, "")
            else:
                value = self.rows[st.key].get_text()
            if st.required and not value:
                raise ValueError(f"{st.title} is needed")
            values[st.key] = value
        return values

    def _say(self, text: str) -> None:
        self.status_label.set_text(text)
        self.status_label.set_visible(bool(text))

    def _on_apply(self, *_args) -> None:
        try:
            values = self.collect()
        except ValueError as exc:
            self._say(str(exc))
            return
        self.apply_button.set_sensitive(False)
        self._say("Applying…")

        def done(lines: list[str]) -> None:
            self.close()
            if self._on_done:
                self._on_done(lines)

        def failed(exc: Exception) -> None:
            self.apply_button.set_sensitive(True)
            self._say(str(exc))

        worker.run(lambda: self.prov.configure(self.ctx, values), done, failed)


class ModulesDialog(Adw.Dialog):
    """The installed provider modules: are their images there, are they running."""

    def __init__(self, toast=None) -> None:
        super().__init__(title="Provider modules", content_width=560, content_height=520)
        self._toast = toast
        page = Adw.PreferencesPage()
        self.group = Adw.PreferencesGroup(
            description="Each module turns an upstream — Tor, a VPN, 9proxy, Mysterium — "
            "into plain SOCKS5 for an exit. Install more with kiwi: "
            "kiwi install kiwi-plugin-tor (or -vpn, -9proxy, -myst)."
        )
        page.add(self.group)
        names = providers.discover()
        if not names:
            self.group.add(_row("No modules installed", "kiwi install kiwi-plugin-tor"))
        for name in names:
            self.group.add(self._module_row(name))
        view = Adw.ToolbarView()
        view.add_top_bar(Adw.HeaderBar())
        view.set_content(page)
        self.set_child(view)

    def _module_row(self, name: str) -> Adw.ActionRow:
        try:
            _prov, manifest = providers.load(name)
            title = manifest.title + (" · account required" if manifest.needs_account else "")
        except providers.ProviderError as exc:
            return _row(name, f"broken: {exc}")
        row = Adw.ActionRow(title=title, subtitle="checking…", use_markup=False)
        row.set_subtitle_lines(0)
        try:
            prov, manifest = providers.load(name)
            has_settings = bool(prov.settings(providers.context_for(name, manifest)))
        except providers.ProviderError:
            has_settings = False
        if has_settings:
            configure = Gtk.Button(label="Configure…", valign=Gtk.Align.CENTER)
            configure.connect("clicked", self._on_configure, name, row)
            row.add_suffix(configure)
        button = Gtk.Button(label="Set up", valign=Gtk.Align.CENTER)
        button.connect("clicked", self._on_setup, name, row)
        row.add_suffix(button)
        self._status(name, row)
        return row

    def _status(self, name: str, row: Adw.ActionRow) -> None:
        def work():
            prov, manifest = providers.load(name)
            ctx = providers.context_for(name, manifest)
            if not podman.available():
                return "podman is not installed"
            status = prov.status(ctx)
            image = "image ready" if status.image_present else "image missing — set it up"
            bits = [name, image, "running" if status.running else "idle"]
            if prov.settings(ctx):
                bits.append(prov.configured(ctx) or "not configured")
            return " · ".join(bits)

        worker.run(work, row.set_subtitle, lambda exc: row.set_subtitle(f"{name} · {exc}"))

    def _on_configure(self, _button, name: str, row: Adw.ActionRow) -> None:
        def done(lines: list[str]) -> None:
            self._status(name, row)
            if self._toast:
                self._toast(lines[0] if lines else f"{name} configured")

        ModuleConfigDialog(name, done).present(self)

    def _on_setup(self, button: Gtk.Button, name: str, row: Adw.ActionRow) -> None:
        from .. import setup

        button.set_sensitive(False)
        row.set_subtitle("building or pulling its image…")

        def done(_r) -> None:
            button.set_sensitive(True)
            self._status(name, row)
            if self._toast:
                self._toast(f"{name}: image ready")

        def failed(exc: Exception) -> None:
            button.set_sensitive(True)
            row.set_subtitle(f"{name} · setup failed: {exc}")

        worker.run(lambda: setup.setup_module(name), done, failed)
