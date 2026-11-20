"""Preferences → Maintenance: the jobs that used to crowd the window's menu
(set up, check, repair, tidy up). Each row runs the window's own action after the
Preferences dialog closes, so its result shows where it always did."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

# (title, a few words, button, the window's action)
Job = tuple[str, str, str, str]


class MaintenancePage(Adw.PreferencesPage):
    def __init__(self, window: Gtk.Window, jobs: list[Job]) -> None:
        super().__init__(title="Maintenance", icon_name="preferences-other-symbolic")
        self._window = window
        group = Adw.PreferencesGroup(title="This computer")
        self.buttons: dict[str, Gtk.Button] = {}
        for title, words, label, action in jobs:
            row = Adw.ActionRow(title=title, subtitle=words, use_markup=False)
            button = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
            button.connect("clicked", lambda _b, a=action: self.run(a))
            row.add_suffix(button)
            group.add(row)
            self.buttons[action] = button
        self.add(group)

    def run(self, action: str) -> None:
        dialog = self.get_ancestor(Adw.PreferencesDialog)
        if dialog is not None:
            dialog.close()
        self._window.activate_action(action, None)


class ModulesPage(Adw.PreferencesPage):
    """Preferences → Modules: every installed provider module with its state, Set
    up, and its settings or wallets, right here."""

    def __init__(self, window: Gtk.Window, installed: list[str] | None = None) -> None:  # noqa: ARG002
        super().__init__(title="Modules", icon_name="application-x-addon-symbolic")
        from .dialogs import ModulesGroup

        self.group = ModulesGroup(self._toast, getattr(window, "_module_configured", None))
        self.add(self.group)

    def _toast(self, text: str) -> None:
        dialog = self.get_ancestor(Adw.PreferencesDialog)
        if dialog is not None:
            dialog.add_toast(Adw.Toast(title=text))
