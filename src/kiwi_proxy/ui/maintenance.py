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
    """Preferences → Modules: which provider modules are installed, and the way to
    their settings (the Provider modules dialog, as before)."""

    def __init__(self, window: Gtk.Window, installed: list[str]) -> None:
        super().__init__(title="Modules", icon_name="application-x-addon-symbolic")
        group = Adw.PreferencesGroup(title="Provider modules")
        row = Adw.ActionRow(
            title="Installed", subtitle=", ".join(installed) or "none", use_markup=False
        )
        manage = Gtk.Button(label="Manage…", valign=Gtk.Align.CENTER)
        manage.connect("clicked", lambda *_: window.activate_action("win.modules", None))
        row.add_suffix(manage)
        group.add(row)
        self.add(group)
