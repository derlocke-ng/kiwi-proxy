"""Adw.Application entry point."""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, Gtk  # noqa: E402

from .. import __version__, paths  # noqa: E402
from .window import Window  # noqa: E402

APP_ID = "dev.kiwinetwork.KiwiProxy"


class Application(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_startup(self) -> None:  # noqa: N802 - GObject naming
        Adw.Application.do_startup(self)
        paths.ensure_tree()
        about = Gio.SimpleAction.new("about", None)
        about.connect("activate", self._on_about)
        self.add_action(about)

    def do_activate(self) -> None:  # noqa: N802
        window = self.props.active_window or Window(application=self)
        window.present()

    def _on_about(self, *_args) -> None:
        dialog = Adw.AboutDialog(
            application_name="Kiwi-Proxy",
            application_icon="kiwi-proxy",
            version=__version__,
            comments="Sealed SOCKS5/VPN exits in rootless Podman — for browsers, "
            "pentest tools, host apps and kiwi-server machines.",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/derlocke-ng/kiwi-proxy",
        )
        dialog.present(self.props.active_window)


def main(argv: list[str] | None = None) -> int:
    return Application().run(argv if argv is not None else sys.argv)
