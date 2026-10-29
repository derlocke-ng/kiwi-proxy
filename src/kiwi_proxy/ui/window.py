"""Main window: the exits, whether each is up, and the setup state behind them."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from .. import dns, exits, gateway, paths, podman  # noqa: E402
from . import worker  # noqa: E402
from .dialogs import ExitDetails, ExitEditor, ModulesDialog, proxy_url  # noqa: E402

REFRESH_SECONDS = 4


class Window(Adw.ApplicationWindow):
    def __init__(self, **kwargs) -> None:
        super().__init__(default_width=760, default_height=620, title="Kiwi-Proxy", **kwargs)
        self._rows: dict[str, Adw.ActionRow] = {}
        self._busy: set[str] = set()
        self._up: dict[str, dict] = {}  # exit id -> gateway row from gateway.running()
        self._polling = False

        self.toasts = Adw.ToastOverlay()
        header = Adw.HeaderBar()

        new_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="New exit")
        new_button.connect("clicked", self._on_new)
        header.pack_start(new_button)

        menu = Gio.Menu()
        menu.append("Provider modules", "win.modules")
        menu.append("Set up environment", "win.setup")
        menu.append("Check environment", "win.doctor")
        menu.append("Tidy up unused gateways", "win.reap")
        menu.append("Take down the exits made here", "win.down-all")
        menu.append("About Kiwi-Proxy", "app.about")
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(menu_button)

        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        self.refresh_button.connect("clicked", lambda *_: self.refresh())
        header.pack_end(self.refresh_button)

        self.status_banner = Adw.Banner(revealed=False)
        self.status_banner.set_button_label("Set up")
        self.status_banner.connect("button-clicked", lambda *_: self._run_setup())

        self.page = Adw.PreferencesPage()
        self.group = Adw.PreferencesGroup(
            title="Exits",
            description="Each exit is a sealed gateway: its only route is one upstream. "
            "Containers join it; with a host port, anything on this computer can use it.",
        )
        self.page.add(self.group)

        self.empty = Adw.StatusPage(
            icon_name="network-vpn-symbolic",
            title="No exits yet",
            description="An exit is one upstream — a SOCKS5 you were given, Tor, a VPN, "
            "9proxy, Mysterium — that browsers, tools and host apps can leave through.",
        )
        create = Gtk.Button(label="Add an exit", halign=Gtk.Align.CENTER)
        create.add_css_class("suggested-action")
        create.add_css_class("pill")
        create.connect("clicked", self._on_new)
        self.empty.set_child(create)

        self.stack = Gtk.Stack()
        self.stack.add_named(self.page, "list")
        self.stack.add_named(self.empty, "empty")

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.add_top_bar(self.status_banner)
        view.set_content(self.stack)
        self.toasts.set_child(view)
        self.set_content(self.toasts)

        for name, handler in (
            ("modules", lambda *_: ModulesDialog(self._toast).present(self)),
            ("setup", lambda *_: self._run_setup()),
            ("doctor", lambda *_: self._check_environment(announce=True)),
            ("reap", lambda *_: self._reap()),
            ("down-all", lambda *_: self._down_all()),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)
        for name, handler in (
            ("details", self._act_details),
            ("edit", self._act_edit),
            ("duplicate", self._act_duplicate),
            ("check", self._act_check),
            ("copy-gateway", self._act_copy_gateway),
            ("delete", self._act_delete),
        ):
            action = Gio.SimpleAction.new(name, GLib.VariantType.new("s"))
            action.connect("activate", handler)
            self.add_action(action)

        self.refresh()
        self._check_environment()
        GLib.timeout_add_seconds(REFRESH_SECONDS, self._tick)

    # ------------------------------------------------------------------ list
    def _tick(self) -> bool:
        self.refresh(rebuild=False)
        return True

    def refresh(self, rebuild: bool = True) -> None:
        found = exits.list_exits()
        self.stack.set_visible_child_name("list" if found else "empty")
        if rebuild:
            for row in self._rows.values():
                self.group.remove(row)
            self._rows.clear()
            for ex in found:
                row = self._build_row(ex)
                self._rows[ex.id] = row
                self.group.add(row)
        for ex in found:
            if row := self._rows.get(ex.id):
                self._update_row(row, ex)
        self._poll()

    def _poll(self) -> None:
        """Which gateways run: one podman call, off the main loop."""
        if self._polling:
            return
        self._polling = True

        def work():
            if not podman.available():
                return {}
            return {
                g["exit_id"]: g
                for g in gateway.running()
                if g["exit_id"] and g["state"] == "running"
            }

        def done(up) -> None:
            self._polling = False
            if up != self._up:
                self._up = up
                for ex in exits.list_exits():
                    if row := self._rows.get(ex.id):
                        self._update_row(row, ex)

        def failed(_exc: Exception) -> None:
            self._polling = False

        worker.run(work, done, failed)

    def _build_row(self, ex) -> Adw.ActionRow:
        row = Adw.ActionRow(title=ex.name, activatable=True, use_markup=False)
        row.connect("activated", lambda *_: self._open_details(ex.id))

        state = Gtk.Image(icon_name="network-offline-symbolic")
        row.add_prefix(state)
        row.state_icon = state  # type: ignore[attr-defined]

        copy = Gtk.Button(
            icon_name="edit-copy-symbolic",
            valign=Gtk.Align.CENTER,
            tooltip_text="Copy the host proxy address",
        )
        copy.add_css_class("flat")
        copy.connect("clicked", self._on_copy_address, ex.id)
        row.add_suffix(copy)
        row.copy_button = copy  # type: ignore[attr-defined]

        toggle = Gtk.Button(valign=Gtk.Align.CENTER)
        toggle.connect("clicked", self._on_toggle, ex.id)
        row.add_suffix(toggle)
        row.toggle_button = toggle  # type: ignore[attr-defined]

        menu = Gio.Menu()
        menu.append("Details", f"win.details::{ex.id}")
        menu.append("Edit…", f"win.edit::{ex.id}")
        menu.append("Duplicate", f"win.duplicate::{ex.id}")
        menu.append("Check the exit", f"win.check::{ex.id}")
        menu.append("Copy gateway name", f"win.copy-gateway::{ex.id}")
        menu.append("Delete", f"win.delete::{ex.id}")
        more = Gtk.MenuButton(
            icon_name="view-more-symbolic", valign=Gtk.Align.CENTER, menu_model=menu
        )
        more.add_css_class("flat")
        row.add_suffix(more)
        return row

    def _update_row(self, row: Adw.ActionRow, ex) -> None:
        up = ex.id in self._up
        bits = [ex.endpoint.label]
        if ex.endpoint.lease or ex.endpoint.country:
            bits[0] += f" ({ex.endpoint.lease or ex.endpoint.country})"
        if ex.expose:
            bits.append(f"host {ex.expose.address}")
        if ex.last_exit:
            bits.append(
                " ".join(x for x in (ex.last_exit.country, ex.last_exit.city) if x)
                or ex.last_exit.ip
            )
        if ex.owner:
            bits.append(f"from {ex.owner}")
        row.set_subtitle(" · ".join(bits))
        row.copy_button.set_visible(bool(ex.expose))  # type: ignore[attr-defined]

        icon = row.state_icon  # type: ignore[attr-defined]
        icon.set_from_icon_name("network-vpn-symbolic" if up else "network-offline-symbolic")
        icon.set_tooltip_text("up" if up else "down")
        for css in ("success", "dim-label"):
            icon.remove_css_class(css)
        icon.add_css_class("success" if up else "dim-label")

        button = row.toggle_button  # type: ignore[attr-defined]
        if ex.id in self._busy:
            button.set_label("Working…")
            button.set_sensitive(False)
            return
        button.set_sensitive(True)
        button.set_label("Take down" if up else "Bring up")
        for css in ("suggested-action", "destructive-action"):
            button.remove_css_class(css)
        button.add_css_class("destructive-action" if up else "suggested-action")

    # --------------------------------------------------------------- actions
    def _exit(self, ident: str):
        return next((e for e in exits.list_exits() if e.id == ident), None)

    def _open_details(self, ident: str) -> None:
        if ex := self._exit(ident):
            ExitDetails(ex, self._after_edit, self._toast).present(self)

    def _act_details(self, _action, param) -> None:
        self._open_details(param.get_string())

    def _act_edit(self, _action, param) -> None:
        if ex := self._exit(param.get_string()):
            ExitEditor(ex, self._after_edit).present(self)

    def _act_duplicate(self, _action, param) -> None:
        if ex := self._exit(param.get_string()):
            ExitEditor(None, self._after_create, template=ex).present(self)

    def _after_edit(self, ex) -> None:
        self.refresh()
        note = " — take it down and up again to apply" if ex.id in self._up else ""
        self._toast(f"Saved {ex.name}{note}")

    def _act_check(self, _action, param) -> None:
        ex = self._exit(param.get_string())
        if not ex:
            return
        if ex.id not in self._up:
            self._toast(f"{ex.name} is down; bring it up first")
            return

        def work():
            info = gateway.measure_exit(paths.gateway_name(ex.id))
            exits.record_exit(ex, info)
            return info

        def done(info) -> None:
            self.refresh(rebuild=False)
            place = " ".join(x for x in (info.country, info.city) if x)
            self._toast(f"{ex.name}: {info.ip} {place}".rstrip())

        worker.run(work, done, lambda exc: self._alert(f"Could not check {ex.name}", str(exc)))

    def _act_copy_gateway(self, _action, param) -> None:
        if ex := self._exit(param.get_string()):
            self._copy(
                paths.gateway_name(ex.id),
                "Gateway name copied — join it with --network container:…",
            )

    def _on_copy_address(self, _button, ident: str) -> None:
        ex = self._exit(ident)
        if ex and ex.expose:
            self._copy(proxy_url(ex), f"Copied {proxy_url(ex)}")

    def _copy(self, text: str, toast: str) -> None:
        Gdk.Display.get_default().get_clipboard().set(text)
        self._toast(toast)

    def _act_delete(self, _action, param) -> None:
        ex = self._exit(param.get_string())
        if not ex:
            return
        if ex.owner:
            self._alert(
                f"{ex.name} belongs to {ex.owner}",
                f"Remove it in {ex.owner}; deleting it here would leave {ex.owner} pointing at "
                "an exit that no longer exists.",
            )
            return
        dialog = Adw.AlertDialog(
            heading=f"Delete {ex.name}?",
            body="The gateway is taken down, with anything that joined it, and the exit's "
            "stored passwords are removed.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def on_response(_d, response: str) -> None:
            if response != "delete":
                return

            def work():
                gateway.down(ex.id)
                exits.delete(ex.id)

            def done(_r) -> None:
                self.refresh()
                self._toast(f"Deleted {ex.name}")

            worker.run(work, done, lambda exc: self._alert(f"Could not delete {ex.name}", str(exc)))

        dialog.connect("response", on_response)
        dialog.present(self)

    def _on_new(self, *_args) -> None:
        ExitEditor(None, self._after_create).present(self)

    def _after_create(self, ex) -> None:
        self.refresh()
        self._toast(f"Added {ex.name}")

    def _on_toggle(self, _button, ident: str) -> None:
        ex = self._exit(ident)
        if not ex:
            return
        if ident in self._up:
            self._confirm_down(ex)
            return
        self._busy.add(ident)
        self.refresh(rebuild=False)

        def done(gw) -> None:
            self._busy.discard(ident)
            self._up[ident] = {"name": gw.name}
            self.refresh()
            for note in gw.notes:
                self._toast(note)
            where = f" — {gw.info.ip} {gw.info.country or ''}".rstrip() if gw.info else ""
            self._toast(f"{ex.name} is up{where}")

        def failed(exc: Exception) -> None:
            self._busy.discard(ident)
            self.refresh()
            self._alert(f"Could not bring {ex.name} up", str(exc))

        # Held, exactly like `kiwi-proxy up`: it stays until taken down here.
        worker.run(lambda: gateway.up(ex, keep=True), done, failed)

    def _confirm_down(self, ex) -> None:
        def work():
            return podman.dependents(paths.gateway_name(ex.id))

        def ask(members) -> None:
            if not members:
                self._down(ex)
                return
            dialog = Adw.AlertDialog(
                heading=f"Take {ex.name} down?",
                body="These are inside it and lose their connection with it:\n\n"
                + "\n".join(members),
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("down", "Take down")
            dialog.set_response_appearance("down", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.connect("response", lambda _d, r: r == "down" and self._down(ex))
            dialog.present(self)

        worker.run(work, ask, lambda _exc: self._down(ex))

    def _down(self, ex) -> None:
        self._busy.add(ex.id)
        self.refresh(rebuild=False)

        def done(_r) -> None:
            self._busy.discard(ex.id)
            self._up.pop(ex.id, None)
            self.refresh()
            self._toast(f"{ex.name} is down")

        def failed(exc: Exception) -> None:
            self._busy.discard(ex.id)
            self.refresh()
            self._alert(f"Could not take {ex.name} down", str(exc))

        worker.run(lambda: gateway.down(ex.id), done, failed)

    def _down_all(self) -> None:
        def work():
            for ex in exits.list_exits():
                if gateway.is_up(ex.id) and not ex.owner:
                    gateway.down(ex.id)

        worker.run(work, lambda _r: (self.refresh(), self._toast("The exits made here are down")))

    def _reap(self) -> None:
        def done(cleaned) -> None:
            self.refresh()
            self._toast(", ".join(cleaned) + " torn down" if cleaned else "Nothing to tidy up")

        worker.run(gateway.reap, done, lambda exc: self._alert("Could not tidy up", str(exc)))

    # ----------------------------------------------------------- environment
    def _check_environment(self, announce: bool = False) -> None:
        def work():
            from .. import setup

            missing = []
            if not podman.available():
                return ["podman"]
            for image, name in setup.IMAGES:
                state = setup.image_state(image, name)
                if state != "current":
                    missing.append(f"{name} image ({state})")
            if not dns.load_stamps():
                missing.append("DNS resolver stamps")
            if not (paths.blocklists_dir() / "blocked-names.txt").exists():
                missing.append("blocklist")
            return missing

        def done(missing) -> None:
            if missing:
                self.status_banner.set_title("Setup incomplete: " + ", ".join(missing))
                self.status_banner.set_revealed(True)
            else:
                self.status_banner.set_revealed(False)
                if announce:
                    self._toast("Environment is ready")

        worker.run(work, done)

    def _run_setup(self) -> None:
        from .. import setup

        progress = Adw.AlertDialog(heading="Setting up", body="Starting…")
        progress.add_response("close", "Run in background")
        progress.present(self)

        def say(message: str) -> None:
            GLib.idle_add(progress.set_body, message)

        def done(steps) -> None:
            progress.close()
            self._check_environment()
            self.refresh()
            self._alert("Setup finished", "\n".join(steps))

        def failed(exc: Exception) -> None:
            progress.close()
            self._alert("Setup failed", str(exc))

        worker.run(lambda: setup.run(progress=say), done, failed)

    # ---------------------------------------------------------------- toasts
    def _toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=4))

    def _alert(self, heading: str, body: str) -> None:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("ok", "OK")
        dialog.present(self)
