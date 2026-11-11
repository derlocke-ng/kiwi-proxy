"""Main window: the exits, whether each is up, and the setup state behind them."""

from __future__ import annotations

import json

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from .. import dns, exits, gateway, paths, podman, selection, snapshots, storage  # noqa: E402
from ..snapshots import items as snapshot_items  # noqa: E402
from . import help as help_ui  # noqa: E402
from . import snapshots as snapshot_ui  # noqa: E402
from . import storage as storage_ui  # noqa: E402
from . import worker  # noqa: E402
from .dialogs import ExitDetails, ExitEditor, ModulesDialog, proxy_url  # noqa: E402

# How often the snapshot folder is looked at (in window ticks): a sync client
# brings new snapshots now and then, not every few seconds.
SNAPSHOT_TICKS = 5

# A window large enough for the largest dialog (the picker is 720×780) to open at
# its own size instead of being squeezed; the size it had when last closed wins.
DEFAULT_SIZE = (1040, 840)
MIN_SIZE = (640, 480)


def saved_geometry() -> tuple[int, int, bool]:
    """(width, height, maximized) from config/window.json, else the default."""
    try:
        d = json.loads((paths.config_dir() / "window.json").read_text())
        width = max(int(d["width"]), MIN_SIZE[0])
        height = max(int(d["height"]), MIN_SIZE[1])
        return width, height, bool(d.get("maximized"))
    except (OSError, ValueError, KeyError, TypeError):
        return DEFAULT_SIZE[0], DEFAULT_SIZE[1], False


def remember_geometry(window) -> None:
    """Keep the window's size for the next start. GTK 4 tracks the user's resizing
    in the default size, and keeps the un-maximized one while maximized."""
    width, height = window.get_default_size()
    try:
        paths.config_dir().mkdir(parents=True, exist_ok=True)
        (paths.config_dir() / "window.json").write_text(
            json.dumps({"width": width, "height": height, "maximized": window.is_maximized()})
        )
    except OSError:
        pass


REFRESH_SECONDS = 4


def _members_of(ex) -> list[str]:
    """Who is inside the exit's gateway, each marked when kiwi-proxy keeps it as an
    image before removing it (a Kiwi Custodia box)."""
    lines = []
    for member in podman.dependents(paths.gateway_name(ex.id)):
        image = gateway.kept_as(member)
        lines.append(f"{member} — kept as an image first" if image else member)
    return lines


class Window(Adw.ApplicationWindow):
    def __init__(self, **kwargs) -> None:
        width, height, maximized = saved_geometry()
        super().__init__(default_width=width, default_height=height, title="Kiwi Proxy", **kwargs)
        if maximized:
            self.maximize()
        self.connect("close-request", self._on_close_request)
        self._rows: dict[str, Adw.ActionRow] = {}
        self._busy: set[str] = set()
        self._up: dict[str, dict] = {}  # exit id -> gateway row from gateway.running()
        self._polling = False
        # What the snapshot folder says, refreshed every SNAPSHOT_TICKS ticks:
        # relations of this device's exits, and items that are only in the folder.
        self._relations: dict[str, snapshots.Relation] = {}
        self._away: list[tuple[str, str, str, list[snapshots.Meta]]] = []
        self._away_rows: list[Adw.ActionRow] = []
        self._snap_polling = False
        self._ticks = 0

        self.toasts = Adw.ToastOverlay()
        header = Adw.HeaderBar()

        new_button = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="New exit")
        new_button.connect("clicked", self._on_new)
        header.pack_start(new_button)

        menu = Gio.Menu()
        menu.append("Preferences", "win.preferences")
        menu.append("Provider modules", "win.modules")
        menu.append("Snapshot everything now", "win.snapshot-all")
        menu.append("Set up environment", "win.setup")
        menu.append("Check environment", "win.doctor")
        menu.append("Check and repair", "win.storage")
        menu.append("Tidy up unused gateways", "win.reap")
        menu.append("Take down the exits made here", "win.down-all")
        menu.append("About Kiwi Proxy", "app.about")
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(menu_button)

        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh")
        self.refresh_button.connect("clicked", lambda *_: self.refresh())
        header.pack_end(self.refresh_button)

        self.status_banner = Adw.Banner(revealed=False)
        self.status_banner.set_button_label("Set up")
        self.status_banner.connect("button-clicked", lambda *_: self._run_setup())
        self.snap_banner = Adw.Banner(
            title="Snapshots are locked on this device", button_label="Unlock", revealed=False
        )
        self.snap_banner.connect(
            "button-clicked", lambda *_: snapshot_ui.ask_unlock(self, self._snapshots_changed)
        )

        self.page = Adw.PreferencesPage()
        help_ui.widen(self.page)
        self.group = Adw.PreferencesGroup(title="Exits")
        help_ui.explain(
            self.group,
            "Each exit is a sealed gateway: its only route is one upstream. Containers "
            "(Kiwi Fox's browsers, Kiwi Custodia's boxes) join it; with a host port, any "
            "application on this computer can use it.",
            app="kiwi-proxy",
        )
        self.page.add(self.group)
        self.away_group = Adw.PreferencesGroup(
            title="In your snapshot folder, not on this device", visible=False
        )
        self.page.add(self.away_group)

        self.empty = Adw.StatusPage(
            icon_name="network-vpn-symbolic",
            title="No exits yet",
            description="One upstream for browsers, boxes and apps to leave through",
        )
        create = Gtk.Button(label="Add an exit", halign=Gtk.Align.CENTER)
        create.add_css_class("suggested-action")
        create.add_css_class("pill")
        create.connect("clicked", self._on_new)
        from_folder = Gtk.Button(label="Use a snapshot folder", halign=Gtk.Align.CENTER)
        from_folder.add_css_class("pill")
        from_folder.set_tooltip_text("Bring the exits of another device here, from snapshots")
        from_folder.connect(
            "clicked", lambda *_: snapshot_ui.choose_folder(self, self._snapshots_changed)
        )
        buttons = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, halign=Gtk.Align.CENTER)
        buttons.append(create)
        buttons.append(from_folder)
        self.empty.set_child(buttons)

        self.stack = Gtk.Stack()
        self.stack.add_named(self.page, "list")
        self.stack.add_named(self.empty, "empty")

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.add_top_bar(self.status_banner)
        view.add_top_bar(self.snap_banner)
        view.set_content(self.stack)
        self.toasts.set_child(view)
        self.set_content(self.toasts)

        for name, handler in (
            ("preferences", lambda *_: self._open_preferences()),
            ("snapshot-all", lambda *_: self._snapshot_all()),
            (
                "modules",
                lambda *_: ModulesDialog(self._toast, self._module_configured).present(self),
            ),
            ("setup", lambda *_: self._run_setup()),
            ("doctor", lambda *_: self._check_environment(announce=True)),
            ("reap", lambda *_: self._reap()),
            ("storage", lambda *_: storage_ui.check_and_repair(self, self.refresh)),
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
            ("snapshots", self._act_snapshots),
            ("nyx", self._act_nyx),
            ("forget-snapshots", self._act_forget_snapshots),
        ):
            action = Gio.SimpleAction.new(name, GLib.VariantType.new("s"))
            action.connect("activate", handler)
            self.add_action(action)

        self.refresh()
        self._check_environment()
        self._repair_on_start()
        GLib.timeout_add_seconds(REFRESH_SECONDS, self._tick)

    # ------------------------------------------------------------------ list
    def _on_close_request(self, *_args) -> bool:
        remember_geometry(self)
        return False  # and close

    def _tick(self) -> bool:
        self._ticks += 1
        if self._ticks % SNAPSHOT_TICKS == 0:
            self._poll_snapshots()
        self.refresh(rebuild=False)
        return True

    def refresh(self, rebuild: bool = True) -> None:
        found = exits.list_exits()
        self.stack.set_visible_child_name("list" if found or self._away else "empty")
        self.group.set_visible(bool(found))
        if rebuild:
            self._poll_snapshots()
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
            found = {}
            for g in gateway.running():
                if not g["exit_id"] or g["state"] != "running":
                    continue
                try:
                    g["provider_alive"] = gateway.provider_alive(exits.load(g["exit_id"]))
                except exits.ExitError:
                    g["provider_alive"] = None
                found[g["exit_id"]] = g
            return found

        def done(up) -> None:
            self._polling = False
            if any(g.get("provider_alive") is False for g in up.values()):
                # A tunnel node that failed closed: start it again behind its
                # gateway, off the main loop, and look again when it is done.
                worker.run(gateway.heal, lambda healed: self._poll(), lambda _exc: None)
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
        if selection.supports(ex.endpoint.module):
            menu.append("Tor monitor (nyx)", f"win.nyx::{ex.id}")
        menu.append("Snapshots…", f"win.snapshots::exit:{ex.id}")
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
        if chosen := selection.summary(ex.endpoint):
            bits[0] += f" ({chosen})"
        elif ex.endpoint.lease or ex.endpoint.country:
            bits[0] += f" ({ex.endpoint.lease or ex.endpoint.country})"
        if ex.expose:
            bits.append(f"host {ex.expose.address}")
        if ex.last_exit:
            bits.append(
                " ".join(x for x in (ex.last_exit.country, ex.last_exit.city) if x)
                or ex.last_exit.ip
            )
        if up and self._up.get(ex.id, {}).get("provider_alive") is False:
            bits.append("provider gone — see its logs")
        if ex.owner:
            bits.append(f"from {ex.owner}")
        rel = self._relations.get(ex.id)
        if rel and rel.newer_elsewhere:
            bits.append(rel.describe())
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
        self._auto_snapshot(ex)

    def _auto_snapshot(self, ex) -> None:
        """The automatic snapshot after an exit was added or changed, off the main
        loop; a toast only when it could not be taken."""

        def done(note) -> None:
            if note:
                self._toast(note)
            self._poll_snapshots()

        worker.run(lambda: snapshot_items.auto_exit(ex), done, lambda _exc: None)

    def _module_configured(self, name: str) -> None:
        def done(note) -> None:
            if note:
                self._toast(note)
            self._poll_snapshots()

        worker.run(lambda: snapshot_items.auto_module(name), done, lambda _exc: None)

    def _act_check(self, _action, param) -> None:
        ex = self._exit(param.get_string())
        if not ex:
            return
        up_now = ex.id in self._up
        if not up_now:
            self._toast(f"{ex.name} is down — bringing it up for the check")

        def work():
            return gateway.probe(ex)

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
        self._auto_snapshot(ex)

    def _on_toggle(self, _button, ident: str) -> None:
        ex = self._exit(ident)
        if not ex:
            return
        if ident in self._up:
            self._confirm_down(ex)
            return
        rel = self._relations.get(ident)
        s = snapshots.load_settings()
        if rel and rel.newer_elsewhere and s and s.ask_older:

            def restore_then_up() -> None:
                def work():
                    assert rel.head is not None
                    return snapshot_items.restore_exit(ident, rel.head.id)

                def done(restored) -> None:
                    self._relations.pop(ident, None)
                    self.refresh()
                    self._bring_up(restored)

                worker.run(
                    work, done, lambda exc: self._alert(f"Could not restore {ex.name}", str(exc))
                )

            def keep_mine() -> None:
                def work():
                    return snapshot_items.take_exit(ex, supersede=rel.heads)

                def done(_meta) -> None:
                    self._relations.pop(ident, None)
                    self._poll_snapshots()
                    self._bring_up(ex)

                worker.run(work, done, lambda exc: self._alert("No snapshot taken", str(exc)))

            snapshot_ui.ask_newer(
                self,
                ex.name,
                rel,
                verb="bring up",
                on_restore=restore_then_up,
                on_as_is=lambda: self._bring_up(ex),
                on_keep_mine=keep_mine,
            )
            return
        self._bring_up(ex)

    def _bring_up(self, ex) -> None:
        ident = ex.id
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
            return _members_of(ex)

        def ask(members) -> None:
            if not members:
                self._down(ex)
                return
            self._ask_down(f"Take {ex.name} down?", members, lambda: self._down(ex))

        # Not knowing who is inside is no reason to go ahead.
        worker.run(
            work, ask, lambda exc: self._alert(f"Could not see who uses {ex.name}", str(exc))
        )

    def _ask_down(self, heading: str, members: list[str], go) -> None:
        dialog = Adw.AlertDialog(
            heading=heading,
            body="These are inside; they lose their connection and are removed with it:\n\n"
            + "\n".join(members),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("down", "Take down")
        dialog.set_response_appearance("down", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.connect("response", lambda _d, r: r == "down" and go())
        dialog.present(self)

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
        def mine():
            return [ex for ex in exits.list_exits() if gateway.is_up(ex.id) and not ex.owner]

        def who():
            return [m for ex in mine() for m in _members_of(ex)]

        def work():
            for ex in mine():
                gateway.down(ex.id)

        def go() -> None:
            worker.run(
                work, lambda _r: (self.refresh(), self._toast("The exits made here are down"))
            )

        def ask(members) -> None:
            if members:
                self._ask_down("Take every exit made here down?", members, go)
            else:
                go()

        worker.run(who, ask, lambda exc: self._alert("Could not see who uses the exits", str(exc)))

    def _act_nyx(self, _action, param) -> None:
        """nyx in a terminal, for an exit that is up."""
        import shutil
        import subprocess
        import sys

        ex = exits.load(param.get_string())
        if not podman.is_running(paths.gateway_name(ex.id)):
            self._toast(f"Bring {ex.name} up first")
            return
        cmd = [
            shutil.which("kiwi-proxy") or sys.executable,
            *([] if shutil.which("kiwi-proxy") else ["-m", "kiwi_proxy"]),
            "nyx",
            ex.name,
        ]
        for term, flag in (
            ("ptyxis", "--"),
            ("kgx", "--"),
            ("gnome-terminal", "--"),
            ("konsole", "-e"),
            ("xterm", "-e"),
        ):
            if shutil.which(term):
                subprocess.Popen([term, flag, *cmd], start_new_session=True)  # noqa: S603
                return
        self._toast(f"No terminal found: run kiwi-proxy nyx {ex.name}")

    def _repair_on_start(self) -> None:
        """Remove kiwi-proxy's own containers a crash or a reset left behind."""

        def done(gone) -> None:
            if gone:
                self._toast(f"Removed {len(gone)} container(s) left from an unclean stop")
                self.refresh()

        worker.run(lambda: storage.remove_leftovers("kiwi-proxy"), done, lambda _exc: None)

    def _reap(self) -> None:
        def work():
            return gateway.heal(), gateway.reap()

        def done(result) -> None:
            healed, cleaned = result
            self.refresh()
            bits = []
            if healed:
                bits.append(", ".join(h.split(":")[0] for h in healed) + " healed")
            if cleaned:
                bits.append(", ".join(cleaned) + " torn down")
            self._toast(" · ".join(bits) if bits else "Nothing to tidy up")

        worker.run(work, done, lambda exc: self._alert("Could not tidy up", str(exc)))

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

    # ------------------------------------------------------------- snapshots
    def _poll_snapshots(self) -> None:
        """Read the snapshot folder off the main loop: how this device's exits relate
        to it, and what is in it that is not here."""
        if self._snap_polling:
            return
        self._snap_polling = True

        def work():
            st = snapshots.status()
            if st.settings is None or not st.folder_present or not st.unlocked:
                return st, {}, []
            opened = snapshots.folder()
            local = snapshot_items.local_items()
            grouped: dict[tuple[str, str], list[snapshots.Meta]] = {}
            for meta in opened.metas():
                if meta.kind in (snapshot_items.EXIT, snapshot_items.MODULE):
                    grouped.setdefault((meta.kind, meta.item), []).append(meta)
            relations = {}
            away = []
            for (kind, item), metas in grouped.items():
                if (kind, item) in local:
                    if kind == snapshot_items.EXIT:
                        relations[item] = snapshots.relation(
                            kind, item, here=True, metas=metas, folder_id=opened.id
                        )
                else:
                    away.append((kind, item, metas[0].name, metas))
            away.sort(key=lambda a: (a[0], a[2]))
            return st, relations, away

        def done(result) -> None:
            self._snap_polling = False
            st, relations, away = result
            locked = bool(st.settings and st.folder_present and not st.unlocked)
            self.snap_banner.set_revealed(locked)
            changed = relations != self._relations or [a[:3] for a in away] != [
                a[:3] for a in self._away
            ]
            self._relations = relations
            self._away = away
            if changed:
                self._show_away()
                self.refresh(rebuild=False)

        def failed(_exc: Exception) -> None:
            self._snap_polling = False

        worker.run(work, done, failed)

    def _show_away(self) -> None:
        for row in self._away_rows:
            self.away_group.remove(row)
        self._away_rows = []
        for kind, item, name, metas in self._away:
            head = metas[0]
            what = head.extra.get("label") if kind == snapshot_items.EXIT else "module settings"
            row = Adw.ActionRow(use_markup=False)
            row.set_title(name if kind == snapshot_items.EXIT else f"{name} (module)")
            row.set_subtitle(
                " · ".join(
                    x
                    for x in (
                        what,
                        f"from {head.device}, {snapshots.when_text(head.created)}",
                        snapshots.size_text(head.size),
                    )
                    if x
                )
            )
            restore = Gtk.Button(label="Restore", valign=Gtk.Align.CENTER)
            restore.connect("clicked", self._on_restore_away, kind, item, name, head.id)
            row.add_suffix(restore)
            menu = Gio.Menu()
            menu.append("Snapshots…", f"win.snapshots::{kind}:{item}")
            menu.append("Delete from the snapshot folder", f"win.forget-snapshots::{kind}:{item}")
            more = Gtk.MenuButton(
                icon_name="view-more-symbolic", valign=Gtk.Align.CENTER, menu_model=menu
            )
            more.add_css_class("flat")
            row.add_suffix(more)
            self.away_group.add(row)
            self._away_rows.append(row)
        self.away_group.set_visible(bool(self._away))
        self.stack.set_visible_child_name(
            "list" if self._rows or self._away or exits.list_exits() else "empty"
        )

    def _restore_item(self, kind: str, item: str, sid: str):
        if kind == snapshot_items.EXIT:
            return snapshot_items.restore_exit(item, sid)
        return snapshot_items.restore_module(item, sid)

    def _on_restore_away(self, _button, kind: str, item: str, name: str, sid: str) -> None:
        def done(_r) -> None:
            self._toast(f"Restored {name}")
            self._snapshots_changed()

        worker.run(
            lambda: self._restore_item(kind, item, sid),
            done,
            lambda exc: self._alert(f"Could not restore {name}", str(exc)),
        )

    def _snapshots_changed(self) -> None:
        self._relations = {}
        self.refresh()

    def _open_preferences(self) -> None:
        from .prefs import DnsPage
        from .tor import TorPage

        page = snapshot_ui.SnapshotsPage(
            "after an exit or a module changes",
            on_changed=self._snapshots_changed,
            take_all=snapshot_items.take_all,
            take_all_text="every exit and module",
        )
        snapshot_ui.preferences_dialog(DnsPage(), TorPage(), page).present(self)

    def _snapshot_all(self) -> None:
        """Every exit and every module's settings, now."""
        if not snapshots.load_settings():
            self._open_preferences()
            return
        if not snapshots.unlocked():
            snapshot_ui.ask_unlock(self, self._snapshot_all)
            return
        self._toast("Taking snapshots…")

        def done(summary: str) -> None:
            self._toast(f"Snapshots taken: {summary}")
            self._snapshots_changed()

        worker.run(
            snapshot_items.take_all, done, lambda exc: self._alert("No snapshot taken", str(exc))
        )

    def _parse_item(self, param) -> tuple[str, str]:
        kind, _, item = param.get_string().partition(":")
        return kind, item

    def _act_snapshots(self, _action, param) -> None:
        kind, item = self._parse_item(param)
        if not snapshots.load_settings():
            self._open_preferences()
            return
        if not snapshots.unlocked():
            snapshot_ui.ask_unlock(self, lambda: self._act_snapshots(_action, param))
            return
        here = (kind, item) in snapshot_items.local_items()
        if kind == snapshot_items.EXIT:
            ex = self._exit(item)
            name = ex.name if ex else next((a[2] for a in self._away if a[1] == item), item)
            take = (lambda: snapshot_items.take_exit(exits.load(item))) if here else None
        else:
            name = item
            take = (lambda: snapshot_items.take_module(item)) if here else None
        snapshot_ui.HistoryDialog(
            kind,
            item,
            name,
            here=here,
            take=take,
            restore=lambda sid: self._restore_item(kind, item, sid),
            on_changed=self._snapshots_changed,
            toast=self._toast,
        ).present(self)

    def _act_forget_snapshots(self, _action, param) -> None:
        kind, item = self._parse_item(param)
        name = next((a[2] for a in self._away if a[0] == kind and a[1] == item), item)
        dialog = Adw.AlertDialog(
            heading=f"Delete the snapshots of {name}?",
            body="Every snapshot of it is deleted from the snapshot folder, on every device "
            "that syncs the folder. This cannot be undone.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_close_response("cancel")

        def on_response(_d, response: str) -> None:
            if response != "delete":
                return
            worker.run(
                lambda: snapshots.forget(kind, item),
                lambda n: (
                    self._toast(f"Deleted {n} snapshot(s) of {name}"),
                    self._snapshots_changed(),
                ),
                lambda exc: self._alert("Could not delete", str(exc)),
            )

        dialog.connect("response", on_response)
        dialog.present(self)

    # ---------------------------------------------------------------- toasts
    def _toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=4))

    def _alert(self, heading: str, body: str) -> None:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("ok", "OK")
        dialog.present(self)
