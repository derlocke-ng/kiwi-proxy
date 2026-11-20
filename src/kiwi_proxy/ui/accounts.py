"""A module's accounts (Mysterium's wallets): the list, and one account's page.

The module does the work through kiwi-proxy's account hooks (providers.accounts,
account_new, account_act, …); these dialogs only show what it says and ask.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import providers  # noqa: E402
from . import worker  # noqa: E402
from .dialogs import ModuleConfigDialog, _row  # noqa: E402
from .help import explain  # noqa: E402


def plural_title(noun: str) -> str:
    """ "wallet" → "Wallets", for a button and a group title."""
    return noun[:1].upper() + noun[1:] + "s"


def _status_label(page: Adw.PreferencesPage) -> Gtk.Label:
    label = Gtk.Label(wrap=True, xalign=0, visible=False)
    label.add_css_class("dim-label")
    group = Adw.PreferencesGroup()
    group.add(label)
    page.add(group)
    return label


class AccountsDialog(Adw.Dialog):
    """A module's accounts: one row each with its state; New and Import in the
    header; a row opens the account."""

    def __init__(self, name: str, toast=None, on_changed=None) -> None:
        self.name = name
        self.noun = providers.account_noun(name)
        _prov, self.manifest = providers.load(name)
        super().__init__(
            title=f"{self.manifest.title} {self.noun}s", content_width=560, content_height=560
        )
        self._toast = toast
        self._on_changed = on_changed
        self.page = Adw.PreferencesPage()
        self.group = Adw.PreferencesGroup(title=plural_title(self.noun))
        explain(
            self.group,
            f"Each exit on {self.manifest.title} pays from one {self.noun}, chosen in the "
            f"exit's dialog. New makes a {self.noun}; Import takes one you already have.",
            app="providers",
        )
        self.page.add(self.group)
        self._rows: list[Gtk.Widget] = []
        self.status = _status_label(self.page)

        header = Adw.HeaderBar()
        new = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=f"New {self.noun}")
        new.connect("clicked", self._on_new)
        imp = Gtk.Button(icon_name="document-open-symbolic", tooltip_text=f"Import a {self.noun}")
        imp.connect("clicked", self._on_import)
        header.pack_start(new)
        header.pack_start(imp)
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(self.page)
        self.set_child(view)
        self.reload(refresh=False)
        self.reload(refresh=True)

    def _say(self, text: str) -> None:
        self.status.set_text(text)
        self.status.set_visible(bool(text))

    def reload(self, *, refresh: bool) -> None:
        if refresh:
            self._say(f"Asking for each {self.noun}'s balance…")

        def done(found: list) -> None:
            if refresh:
                self._say("")
            self.show(found)

        worker.run(
            lambda: providers.accounts(self.name, refresh=refresh),
            done,
            lambda exc: self._say(str(exc)),
        )

    def show(self, found: list) -> None:
        for row in self._rows:
            self.group.remove(row)
        self._rows = []
        if not found:
            row = _row(f"No {self.noun}s yet", "New makes one; Import takes yours")
            self.group.add(row)
            self._rows.append(row)
        for acc in found:
            row = Adw.ActionRow(
                title=acc.name, subtitle=acc.state or acc.id, use_markup=False, activatable=True
            )
            row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            row.connect("activated", self._on_open, acc)
            self.group.add(row)
            self._rows.append(row)

    def _changed(self, lines: list[str] | None = None) -> None:
        if lines and self._toast:
            self._toast(lines[0])
        self.reload(refresh=False)
        if self._on_changed:
            self._on_changed(self.name)

    def _on_open(self, _row, acc) -> None:
        AccountDialog(self.name, acc, toast=self._toast, on_changed=self._changed).present(self)

    def _on_new(self, *_a) -> None:
        try:
            settings = providers.account_new_settings(self.name)
        except providers.ProviderError as exc:
            self._say(str(exc))
            return
        ModuleConfigDialog(
            self.name,
            self._changed,
            title=f"New {self.noun}",
            settings=settings,
            apply=lambda values: providers.account_new(self.name, values),
            primary="Create",
            description=f"A new {self.manifest.title} {self.noun}, kept on this computer.",
        ).present(self)

    def _on_import(self, *_a) -> None:
        ModuleConfigDialog(
            self.name, self._changed, title=f"Import a {self.noun}", primary="Import"
        ).present(self)


class AccountDialog(Adw.Dialog):
    """One account: its address with a copy button, its state, what the module
    can do with it, its history, and rename, export and remove. While the module
    says it waits on something (a top-up), it asks again every 30 seconds."""

    WATCH_SECONDS = 30

    def __init__(self, name: str, acc, toast=None, on_changed=None) -> None:
        self.name = name
        self.acc = acc
        self.noun = providers.account_noun(name)
        super().__init__(title=acc.name, content_width=600, content_height=680)
        self._toast = toast
        self._on_changed = on_changed
        self._watch_id = 0
        self.page = Adw.PreferencesPage()
        self.main = Adw.PreferencesGroup()
        self.page.add(self.main)
        self.actions = Adw.PreferencesGroup()
        self.page.add(self.actions)
        self.history = Adw.PreferencesGroup(title="History")
        self.page.add(self.history)
        manage = Adw.PreferencesGroup()
        self.name_row = Adw.EntryRow(title="Name", text=acc.name, show_apply_button=True)
        self.name_row.connect("apply", self._on_rename)
        manage.add(self.name_row)
        export = Adw.ButtonRow(title="Export…")
        export.connect("activated", self._on_export)
        manage.add(export)
        remove = Adw.ButtonRow(title=f"Remove {self.noun}…")
        remove.add_css_class("destructive-action")
        remove.connect("activated", self._on_remove)
        manage.add(remove)
        self.page.add(manage)
        self.status = _status_label(self.page)
        self._main_rows: list[Gtk.Widget] = []
        self._action_rows: list[Gtk.Widget] = []
        self._history_rows: list[Gtk.Widget] = []
        self.show(acc)

        header = Adw.HeaderBar()
        refresh = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Ask again")
        refresh.connect("clicked", lambda *_a: self.refresh())
        header.pack_start(refresh)
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(self.page)
        self.set_child(view)
        self.connect("closed", self._on_closed)
        self.load_history()
        self.refresh()

    def _say(self, text: str) -> None:
        self.status.set_text(text)
        self.status.set_visible(bool(text))

    def show(self, acc) -> None:
        self.acc = acc
        for row in self._main_rows:
            self.main.remove(row)
        for row in self._action_rows:
            self.actions.remove(row)
        self._main_rows, self._action_rows = [], []
        rows = []
        if acc.address:
            row = _row(
                acc.address_note or "Address", acc.address, copy=acc.address, toast=self._toast
            )
            row.set_subtitle_selectable(True)
            row.set_subtitle_lines(0)
            rows.append(row)
        rows.append(_row("State", acc.state or "not known yet"))
        if acc.detail:
            row = _row("Details", acc.detail)
            row.set_subtitle_lines(0)
            rows.append(row)
        rows.append(_row("Id", acc.id, copy=acc.id, toast=self._toast))
        for row in rows:
            self.main.add(row)
            self._main_rows.append(row)
        for action in acc.actions:
            button = Adw.ButtonRow(title=action.label)
            button.connect("activated", self._on_action, action)
            self.actions.add(button)
            self._action_rows.append(button)
        self.actions.set_visible(bool(acc.actions))
        self._arm_watch()

    # ------------------------------------------------------------------ watch
    def _arm_watch(self) -> None:
        if self._watch_id:
            GLib.source_remove(self._watch_id)
            self._watch_id = 0
        if self.acc.watch:

            def tick() -> bool:
                self._watch_id = 0
                self.refresh(quiet=True)
                return False

            self._watch_id = GLib.timeout_add_seconds(self.WATCH_SECONDS, tick)

    def _on_closed(self, *_a) -> None:
        if self._watch_id:
            GLib.source_remove(self._watch_id)
            self._watch_id = 0

    def refresh(self, *, quiet: bool = False) -> None:
        if not quiet:
            self._say("Asking…")

        def done(found: list) -> None:
            self._say("")
            if not found:
                return
            before = self.acc.state
            self.show(found[0])
            if before != found[0].state:
                self.load_history()
                if self._on_changed:
                    self._on_changed()

        def failed(exc: Exception) -> None:
            self._say(str(exc))
            self._arm_watch()

        worker.run(
            lambda: providers.accounts(self.name, refresh=True, only=self.acc.id), done, failed
        )

    def load_history(self) -> None:
        def put(rows: list[Gtk.Widget]) -> None:
            for row in self._history_rows:
                self.history.remove(row)
            self._history_rows = []
            for row in rows:
                self.history.add(row)
                self._history_rows.append(row)

        def done(items: list) -> None:
            rows: list[Gtk.Widget] = []
            for it in items:
                sub = " · ".join(b for b in (it.when, it.detail) if b)
                row = Adw.ActionRow(title=it.what, subtitle=sub, use_markup=False)
                if it.amount:
                    row.add_suffix(Gtk.Label(label=it.amount, css_classes=["dim-label"]))
                rows.append(row)
            put(rows or [_row("Nothing yet", "")])

        worker.run(
            lambda: providers.account_history(self.name, self.acc.id),
            done,
            lambda exc: put([_row("History not available", str(exc))]),
        )

    # ---------------------------------------------------------------- actions
    def _confirm(self, heading: str, body: str, verb: str, then, *, destructive=False) -> None:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("go", verb)
        dialog.set_response_appearance(
            "go",
            Adw.ResponseAppearance.DESTRUCTIVE if destructive else Adw.ResponseAppearance.SUGGESTED,
        )

        def on_response(_d, response: str) -> None:
            if response == "go":
                then()

        dialog.connect("response", on_response)
        dialog.present(self)

    def _on_action(self, _button, action) -> None:
        def run() -> None:
            self._say(f"{action.label}…")

            def done(lines: list[str]) -> None:
                self._say(" ".join(lines))
                self.refresh(quiet=True)
                self.load_history()
                if self._on_changed:
                    self._on_changed(lines)

            worker.run(
                lambda: providers.account_act(self.name, self.acc.id, action.key),
                done,
                lambda exc: self._say(str(exc)),
            )

        if action.confirm:
            self._confirm(action.label, action.confirm, action.label, run)
        else:
            run()

    def _on_rename(self, row) -> None:
        new = row.get_text().strip()
        if not new or new == self.acc.name:
            return

        def done(_r) -> None:
            self.set_title(new)
            if self._on_changed:
                self._on_changed()

        worker.run(
            lambda: providers.account_rename(self.name, self.acc.id, new),
            done,
            lambda exc: self._say(str(exc)),
        )

    def _on_export(self, *_a) -> None:
        dialog = Gtk.FileDialog(title=f"Export {self.acc.name} to a folder")

        def picked(d, result) -> None:
            try:
                folder = d.select_folder_finish(result)
            except GLib.Error:
                return  # cancelled
            if folder is None or not folder.get_path():
                return
            worker.run(
                lambda: providers.account_export(self.name, self.acc.id, folder.get_path()),
                lambda path: self._say(f"Exported to {path}"),
                lambda exc: self._say(str(exc)),
            )

        dialog.select_folder(self.get_root(), None, picked)

    def _on_remove(self, *_a) -> None:
        def run() -> None:
            def done(lines: list[str]) -> None:
                if self._on_changed:
                    self._on_changed(lines)
                self.close()

            worker.run(
                lambda: providers.account_remove(self.name, self.acc.id),
                done,
                lambda exc: self._say(str(exc)),
            )

        self._confirm(
            f"Remove {self.acc.name}?",
            f"Its key file is moved aside, not deleted, and can be imported again from "
            f"there. Export it first for a copy elsewhere: whatever is in a {self.noun} "
            f"is lost with its key.",
            "Remove",
            run,
            destructive=True,
        )
