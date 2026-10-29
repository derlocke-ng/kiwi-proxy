"""Dialogs: add or edit an exit, show what an exit is, and the provider modules."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from .. import dns, endpoint, exits, gateway, paths, podman, providers, secrets  # noqa: E402
from ..models import DnsConfig  # noqa: E402
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
        self.lease_row = _combo("Exit", [ANY_LEASE], subtitle="see the module's leases")
        upstream.add(self.lease_row)
        self.country_row = Adw.EntryRow(title="Country (two letters, optional)")
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
            subtitle="by the exit: no ad-blocking, as Tor Browser needs",
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
        else:
            self.endpoint_row.set_text(endpoint_text(ex.endpoint))
        self.country_row.set_text(ex.endpoint.country or "")
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
        self._leases = [None]
        labels = [ANY_LEASE]
        if module:
            try:
                prov, manifest = providers.load(module)
                for lease in prov.leases(providers.context_for(module, manifest)):
                    self._leases.append(lease.id)
                    where = " ".join(x for x in (lease.country, lease.city) if x)
                    labels.append(" · ".join(x for x in (lease.id, lease.label, where) if x))
                self.lease_row.set_subtitle(manifest.description or manifest.title)
            except providers.ProviderError as exc:
                self.lease_row.set_subtitle(f"module is broken: {exc}")
        current = self.ex.endpoint.lease if self.ex and self.ex.endpoint.module == module else None
        if current and current not in self._leases:
            self._leases.append(current)
            labels.append(current)
        self.lease_row.set_model(Gtk.StringList.new(labels))
        self.lease_row.set_selected(self._leases.index(current) if current in self._leases else 0)
        self._refresh()

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
        resolver = DNS_MODES[self.dns_row.get_selected()][0] == "resolver"
        self.upstream_row.set_visible(resolver)
        for row in self.list_rows.values():
            row.set_visible(resolver)
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
            lease = self._leases[self.lease_row.get_selected()]
            country = self.country_row.get_text().strip().lower() or None
            ep = exits.module_endpoint(module, lease=lease, country=country)
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
        up.add(_row("Ad-blocking", lists if lists and ex.dns.mode == "resolver" else "off"))
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
        button = Gtk.Button(label="Set up", valign=Gtk.Align.CENTER)
        button.connect("clicked", self._on_setup, name, row)
        row.add_suffix(button)
        self._status(name, row)
        return row

    def _status(self, name: str, row: Adw.ActionRow) -> None:
        def work():
            prov, manifest = providers.load(name)
            if not podman.available():
                return "podman is not installed"
            status = prov.status(providers.context_for(name, manifest))
            image = "image ready" if status.image_present else "image missing — set it up"
            return f"{name} · {image} · {'running' if status.running else 'idle'}"

        worker.run(work, row.set_subtitle, lambda exc: row.set_subtitle(f"{name} · {exc}"))

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
