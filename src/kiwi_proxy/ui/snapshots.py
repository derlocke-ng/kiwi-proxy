"""The snapshot screens, the same in Kiwi Proxy, Kiwi Fox and Kiwi Custodia.

- :class:`SnapshotsPage` — the Snapshots page of an app's preferences: the folder,
  this device's name, when snapshots are taken, how many are kept, the passphrase.
- :func:`ask_unlock` / :func:`choose_folder` — the passphrase prompts.
- :class:`HistoryDialog` — one item's snapshots, "Snapshot now" and Restore.
- :func:`ask_newer` — before using a copy the folder has a newer snapshot of.

They only call ``kiwi_proxy.snapshots``; what an item *is* (an exit, a profile, a
box) is the calling app's business, handed in as callables.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from .. import snapshots  # noqa: E402
from . import worker  # noqa: E402

KEYRING_NOTE = "kept in this device's keyring"


def _row(title: str, subtitle: str = "") -> Adw.ActionRow:
    row = Adw.ActionRow(use_markup=False)
    row.set_title(title)
    row.set_subtitle(subtitle)
    row.set_subtitle_lines(0)
    return row


def _button(label: str, *css: str) -> Gtk.Button:
    button = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
    for c in css:
        button.add_css_class(c)
    return button


# ---------------------------------------------------------------- passphrase
def _passphrase_dialog(
    heading: str, body: str, *, confirm: bool, action: str
) -> tuple[Adw.AlertDialog, list[Adw.PasswordEntryRow]]:
    dialog = Adw.AlertDialog(heading=heading, body=body)
    box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
    box.add_css_class("boxed-list")
    entries = [Adw.PasswordEntryRow(title="Passphrase")]
    if confirm:
        entries.append(Adw.PasswordEntryRow(title="The same again"))
    for entry in entries:
        box.append(entry)
    dialog.set_extra_child(box)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("ok", action)
    dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("ok")
    dialog.set_close_response("cancel")

    def validate(*_args) -> None:
        text = entries[0].get_text()
        ok = bool(text) and "\n" not in text
        if confirm:
            ok = ok and len(text) >= snapshots.MIN_PASSPHRASE and text == entries[1].get_text()
        dialog.set_response_enabled("ok", ok)

    for entry in entries:
        entry.connect("changed", validate)
        entry.set_activates_default(True)
    validate()
    return dialog, entries


def ask_unlock(
    parent: Gtk.Widget, on_done: Callable[[], None] | None = None, error: str = ""
) -> None:
    """Ask for the passphrase of this device's folder and keep it in the keyring."""
    s = snapshots.load_settings()
    if s is None:
        return
    body = (
        f"The snapshots in {s.folder} are encrypted. Enter the passphrase once; it is then "
        f"{KEYRING_NOTE}."
    )
    dialog, entries = _passphrase_dialog(
        "Unlock your snapshots on this device",
        f"{error}\n\n{body}" if error else body,
        confirm=False,
        action="Unlock",
    )

    def on_response(_d, response: str) -> None:
        if response != "ok":
            return
        secret = entries[0].get_text()

        def failed(exc: Exception) -> None:
            if isinstance(exc, snapshots.BadPassphrase):
                ask_unlock(parent, on_done, "That passphrase does not open the folder.")
            else:
                _alert(parent, "Could not unlock", str(exc))

        worker.run(lambda: snapshots.unlock(secret), lambda _f: on_done and on_done(), failed)

    dialog.connect("response", on_response)
    dialog.present(parent)


def choose_folder(parent: Gtk.Widget, on_done: Callable[[], None] | None = None) -> None:
    """Pick the snapshot folder: join it when it is one, make it one when it is
    not."""
    chooser = Gtk.FileDialog(title="Snapshot folder", modal=True)
    s = snapshots.load_settings()
    if s:
        chooser.set_initial_folder(Gio.File.new_for_path(s.folder))

    def picked(_dialog, result) -> None:
        try:
            gfile = chooser.select_folder_finish(result)
        except Exception:  # noqa: BLE001 - cancelled
            return
        path = Path(gfile.get_path())
        try:
            joining = snapshots.Folder.at(path) is not None
        except snapshots.SnapshotError as exc:
            _alert(parent, "Not a snapshot folder", str(exc))
            return
        _ask_folder_passphrase(parent, path, joining, on_done)

    chooser.select_folder(parent.get_root(), None, picked)


def _ask_folder_passphrase(
    parent: Gtk.Widget,
    path: Path,
    joining: bool,
    on_done: Callable[[], None] | None,
    error: str = "",
) -> None:
    if joining:
        heading, action = "Use this snapshot folder", "Unlock"
        body = (
            f"{path} holds snapshots already. Enter the passphrase it was made with; it is "
            f"then {KEYRING_NOTE}."
        )
    else:
        heading, action = "A new snapshot folder", "Create"
        body = (
            f"Snapshots in {path} will be encrypted with this passphrase. Every device needs it "
            f"once. At least {snapshots.MIN_PASSPHRASE} characters; it cannot be recovered."
        )
    dialog, entries = _passphrase_dialog(
        heading, f"{error}\n\n{body}" if error else body, confirm=not joining, action=action
    )

    def on_response(_d, response: str) -> None:
        if response != "ok":
            return
        secret = entries[0].get_text()

        def failed(exc: Exception) -> None:
            if isinstance(exc, snapshots.BadPassphrase):
                _ask_folder_passphrase(
                    parent, path, joining, on_done, "That passphrase does not open the folder."
                )
            else:
                _alert(parent, "Could not use the folder", str(exc))

        worker.run(lambda: snapshots.setup(path, secret), lambda _r: on_done and on_done(), failed)

    dialog.connect("response", on_response)
    dialog.present(parent)


def _alert(parent: Gtk.Widget, heading: str, body: str) -> None:
    dialog = Adw.AlertDialog(heading=heading, body=body)
    dialog.add_response("ok", "OK")
    dialog.present(parent)


# -------------------------------------------------------------------- page
class SnapshotsPage(Adw.PreferencesPage):
    """The Snapshots page (shared by the three apps; one settings file).

    `automatic_text` says what "automatically" means in this app ("when you add or
    change an exit", "when a profile stops")."""

    def __init__(self, automatic_text: str, on_changed: Callable[[], None] | None = None) -> None:
        super().__init__(title="Snapshots", icon_name="document-save-symbolic")
        self._on_changed = on_changed
        self._syncing = False

        self.folder_row = _row("Folder")
        choose = _button("Choose…")
        choose.connect("clicked", lambda *_: choose_folder(self, self.sync))
        self.folder_row.add_suffix(choose)
        self.device_row = Adw.EntryRow(title="This device is called", show_apply_button=True)
        self.device_row.connect("apply", self._on_device)
        where = Adw.PreferencesGroup(
            title="Where",
            description="One folder for Kiwi Proxy, Kiwi Fox and Kiwi Custodia. Add it to your "
            "sync client (Nextcloud); a snapshot appears there only when it is complete.",
        )
        where.add(self.folder_row)
        where.add(self.device_row)
        self.add(where)

        self.automatic_row = Adw.SwitchRow(title="Snapshot automatically", subtitle=automatic_text)
        self.automatic_row.connect("notify::active", self._on_switch, "automatic")
        self.ask_row = Adw.SwitchRow(
            title="Ask before using an older copy",
            subtitle="when the folder holds a newer snapshot from another device",
        )
        self.ask_row.connect("notify::active", self._on_switch, "ask_older")
        self.keep_row = Adw.SpinRow.new_with_range(1, snapshots.MAX_KEEP, 1)
        self.keep_row.set_title("Keep per item")
        self.keep_row.set_subtitle("the oldest goes when a new one is made")
        self.keep_row.connect("notify::value", self._on_keep)
        self.when = Adw.PreferencesGroup(title="When")
        for r in (self.automatic_row, self.ask_row, self.keep_row):
            self.when.add(r)
        self.add(self.when)

        self.lock_row = _row("Passphrase")
        self.lock_button = _button("Unlock…")
        self.lock_button.connect("clicked", self._on_lock_button)
        self.lock_row.add_suffix(self.lock_button)
        self.crypt = Adw.PreferencesGroup(
            title="Encryption",
            description="Every snapshot is encrypted (gpg, AES-256) before it is written. "
            "Without the passphrase the files are unreadable, names included.",
        )
        self.crypt.add(self.lock_row)
        self.add(self.crypt)
        self.sync()

    # ------------------------------------------------------------- state
    def sync(self) -> None:
        """Show what the settings say now."""
        st = snapshots.status()
        s = st.settings
        self._syncing = True
        try:
            if s is None:
                self.folder_row.set_subtitle(
                    "not chosen yet"
                    + (
                        f" — install {' and '.join(st.missing_tools)} first"
                        if st.missing_tools
                        else ""
                    )
                )
                self.device_row.set_text("")
            else:
                self.folder_row.set_subtitle(
                    s.folder + ("" if st.folder_present else " — not there (not synced yet?)")
                )
                self.device_row.set_text(s.device_name)
                self.automatic_row.set_active(s.automatic)
                self.ask_row.set_active(s.ask_older)
                self.keep_row.set_value(s.keep)
            for widget in (self.device_row, self.when, self.crypt):
                widget.set_sensitive(s is not None)
            if s is not None and st.unlocked:
                self.lock_row.set_subtitle(f"Unlocked on this device — {KEYRING_NOTE}")
                self.lock_button.set_label("Lock this device")
                self.lock_button.set_tooltip_text(
                    "Forget the passphrase here; it is asked for again when needed"
                )
            else:
                self.lock_row.set_subtitle("Locked on this device")
                self.lock_button.set_label("Unlock…")
                self.lock_button.set_tooltip_text(None)
        finally:
            self._syncing = False
        if self._on_changed:
            self._on_changed()

    def _save(self, change: Callable[[snapshots.Settings], None]) -> None:
        if self._syncing:
            return
        s = snapshots.load_settings()
        if s is None:
            return
        change(s)
        snapshots.save_settings(s)
        if self._on_changed:
            self._on_changed()

    def _on_device(self, row: Adw.EntryRow) -> None:
        name = row.get_text().strip()
        if name:
            self._save(lambda s: setattr(s, "device_name", name))

    def _on_switch(self, row: Adw.SwitchRow, _pspec, attr: str) -> None:
        self._save(lambda s: setattr(s, attr, row.get_active()))

    def _on_keep(self, row: Adw.SpinRow, _pspec) -> None:
        self._save(lambda s: setattr(s, "keep", int(row.get_value())))

    def _on_lock_button(self, *_args) -> None:
        if snapshots.unlocked():
            snapshots.lock()
            self.sync()
        else:
            ask_unlock(self, self.sync)


# ------------------------------------------------------------------ history
class HistoryDialog(Adw.Dialog):
    """One item's snapshots, newest first, with Restore on each and "Snapshot now".

    `take()` and `restore(sid)` do the work (they run off the main loop); `here`
    says whether the item is on this device (then "Snapshot now" is offered)."""

    def __init__(
        self,
        kind: str,
        item: str,
        name: str,
        *,
        here: bool,
        take: Callable[[], object] | None,
        restore: Callable[[str], object],
        on_changed: Callable[[], None] | None = None,
        toast: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(title=f"Snapshots of {name}", content_width=640, content_height=560)
        self.kind, self.item, self.name, self.here = kind, item, name, here
        self._take, self._restore = take, restore
        self._on_changed, self._toast = on_changed, toast

        header = Adw.HeaderBar()
        if take is not None and here:
            self.take_button = _button("Snapshot now", "suggested-action")
            self.take_button.connect("clicked", self._on_take)
            header.pack_end(self.take_button)
        self.list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.list.add_css_class("boxed-list")
        self.status = Gtk.Label(xalign=0, wrap=True)
        self.status.add_css_class("dim-label")
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=12,
            margin_top=18,
            margin_bottom=18,
            margin_start=18,
            margin_end=18,
        )
        box.append(self.list)
        box.append(self.status)
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(Gtk.ScrolledWindow(child=box, vexpand=True))
        self.set_child(view)
        self.rows: list[Adw.ActionRow] = []
        self.reload()

    def reload(self) -> None:
        self.status.set_label("reading the snapshot folder…")

        def work():
            s = snapshots.load_settings()
            opened = snapshots.folder()
            metas = opened.metas(self.kind, self.item)
            rel = snapshots.relation(
                self.kind, self.item, here=self.here, metas=metas, folder_id=opened.id
            )
            base = snapshots.base_of(self.kind, self.item, opened.id)
            return s, metas, rel, {m.id: opened.ready(m) for m in metas}, base

        worker.run(work, self._show, lambda exc: self.status.set_label(str(exc)))

    def _show(self, result) -> None:
        s, metas, rel, ready, base = result
        for row in self.rows:
            self.list.remove(row)
        self.rows = []
        current = base if self.here else None
        newest = rel.head.id if rel.head else None
        for meta in metas:
            bits = [meta.device, snapshots.size_text(meta.size)]
            if meta.id == newest and meta.id != current and self.here:
                bits.append("newest")
            if meta.id == current:
                bits.append(
                    "this device's copy, changed since"
                    if rel.state in ("changed_here", "diverged")
                    else "this device's copy"
                )
            if meta.aside:
                bits.append("kept before a restore")
            if not ready[meta.id]:
                bits.append("still arriving")
            row = _row(snapshots.when_text(meta.created).capitalize(), " · ".join(bits))
            if ready[meta.id] and not (meta.id == current and rel.state == "same"):
                button = _button("Restore")
                button.connect("clicked", self._on_restore, meta)
                row.add_suffix(button)
            self.list.append(row)
            self.rows.append(row)
        keep = s.keep if s else 5
        if metas:
            self.status.set_label(
                f"{len(metas)} of {keep} kept. The oldest goes when a new one is made. "
                + (
                    "Restoring first keeps what is here now as a snapshot, so a restore can "
                    "be undone."
                    if self.here
                    else ""
                )
            )
        else:
            self.status.set_label("No snapshot yet.")

    def _on_take(self, button: Gtk.Button) -> None:
        button.set_sensitive(False)

        def done(_r) -> None:
            button.set_sensitive(True)
            self.reload()
            if self._on_changed:
                self._on_changed()

        def failed(exc: Exception) -> None:
            button.set_sensitive(True)
            if isinstance(exc, snapshots.Locked):
                ask_unlock(self, self.reload)
            else:
                _alert(self, "No snapshot taken", str(exc))

        assert self._take is not None
        worker.run(self._take, done, failed)

    def _on_restore(self, _button, meta: snapshots.Meta) -> None:
        when = snapshots.when_text(meta.created)
        if self.here:
            dialog = Adw.AlertDialog(
                heading=f"Restore {self.name}?",
                body=f"This device's {self.name} is replaced by the snapshot from {meta.device}, "
                f"{when}. What is here now is kept as a snapshot first.",
            )
        else:
            dialog = Adw.AlertDialog(
                heading=f"Restore {self.name}?",
                body=f"From {meta.device}, {when}.",
            )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("restore", "Restore")
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_close_response("cancel")

        def on_response(_d, response: str) -> None:
            if response != "restore":
                return

            def done(_r) -> None:
                self.here = True
                self.reload()
                if self._on_changed:
                    self._on_changed()
                if self._toast:
                    self._toast(f"Restored {self.name} from {meta.device}, {when}")

            worker.run(
                lambda: self._restore(meta.id),
                done,
                lambda exc: _alert(self, "Could not restore", str(exc)),
            )

        dialog.connect("response", on_response)
        dialog.present(self)


# -------------------------------------------------------- before using it
def ask_newer(
    parent: Gtk.Widget,
    name: str,
    rel: snapshots.Relation,
    *,
    verb: str,
    on_restore: Callable[[], None],
    on_as_is: Callable[[], None],
    on_keep_mine: Callable[[], None] | None = None,
) -> None:
    """The folder has a newer copy of `name` (or both sides changed): ask before
    using this device's. `verb` is what the user was about to do ("bring up",
    "start")."""
    head = rel.head
    assert head is not None
    when = snapshots.when_text(head.created)
    if rel.state == "diverged":
        dialog = Adw.AlertDialog(
            heading=f"{name} changed on two devices",
            body=f"This device's copy and the snapshot from {head.device}, {when}, both "
            "changed since they parted. Use the snapshot (this device's copy is kept as a "
            "snapshot), or keep this device's copy (it becomes the newest snapshot).",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("mine", "Keep this device's")
        dialog.add_response("restore", f"Use the snapshot and {verb}")
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.SUGGESTED)
    else:
        dialog = Adw.AlertDialog(
            heading=f"A newer snapshot of {name} exists",
            body=f"From {head.device}, {when}. Restoring replaces this device's copy; that copy "
            "is kept as a snapshot first.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("asis", f"{verb.capitalize()} as it is")
        dialog.add_response("restore", f"Restore and {verb}")
        dialog.set_response_appearance("restore", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_close_response("cancel")

    def on_response(_d, response: str) -> None:
        if response == "restore":
            on_restore()
        elif response == "asis":
            on_as_is()
        elif response == "mine":
            (on_keep_mine or on_as_is)()

    dialog.connect("response", on_response)
    dialog.present(parent)


def preferences_dialog(*pages: Adw.PreferencesPage, visible: Adw.PreferencesPage | None = None):
    dialog = Adw.PreferencesDialog(title="Preferences", content_width=760, content_height=700)
    for page in pages:
        dialog.add(page)
    if visible is not None:
        dialog.set_visible_page(visible)
    return dialog
