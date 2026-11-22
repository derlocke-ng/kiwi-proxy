"""News to act on (ui-rules 9): a bar under the header with a line of text,
one button, and ✕.

    notice = Notice()
    view.add_top_bar(header)              # the header bar first
    view.add_top_bar(notice)              # then the notice, under it
    notice.say("2 newer snapshots in your folder: work, shop", "Import",
                self.import_newer, key=("work@3f2a", "shop@91bc"))
    notice.clear()                        # when the news is gone

Not a problem that blocks the app (that is an Adw.Banner) and not a result
(that is a toast): something the user may want to do now, or later. ✕ hides
it until the news changes: `say` with the same `key` stays hidden, a new key
shows it again. The button runs its action and hides the notice; the app shows
it again if the news is still there.

Adw.Banner has one button and no ✕, so this is the kit's own; it looks like
one. It works on libadwaita 1.5 (Ubuntu 24.04).
"""

from __future__ import annotations

from gi.repository import Gdk, Gtk

_CSS = b"""
.kit-notice {
  background-color: alpha(@accent_bg_color, 0.3);
  padding: 6px 6px 6px 18px;
}
.kit-notice label.kit-notice-text { font-weight: bold; }
"""
_css_loaded = False


def _load_css() -> None:
    global _css_loaded
    display = Gdk.Display.get_default()
    if _css_loaded or display is None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS, -1)
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    _css_loaded = True


class Notice(Gtk.Revealer):
    """The bar. Hidden until `say`."""

    def __init__(self) -> None:
        super().__init__(transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN, reveal_child=False)
        _load_css()
        box = Gtk.Box(spacing=12)
        box.add_css_class("kit-notice")
        self.label = Gtk.Label(wrap=True, xalign=0, hexpand=True, valign=Gtk.Align.CENTER)
        self.label.add_css_class("kit-notice-text")
        self.button = Gtk.Button(valign=Gtk.Align.CENTER, visible=False)
        self.button.add_css_class("suggested-action")
        self.button.connect("clicked", self._on_button)
        self.close = Gtk.Button(
            icon_name="window-close-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Dismiss"
        )
        self.close.add_css_class("flat")
        self.close.add_css_class("circular")
        self.close.connect("clicked", self._on_close)
        box.append(self.label)
        box.append(self.button)
        box.append(self.close)
        self.set_child(box)
        self._action = None
        self._key: object = None
        self._dismissed: object = None

    @property
    def shown(self) -> bool:
        return self.get_reveal_child()

    def say(self, text: str, button: str | None = None, on_button=None, *, key=None) -> None:
        """Show `text`, with `button` running `on_button`. A `key` the user
        dismissed with ✕ stays hidden; None is never dismissed for good."""
        if key is not None and key == self._dismissed:
            return
        self._key = key
        self._action = on_button
        self.label.set_text(text)
        self.button.set_label(button or "")
        self.button.set_visible(bool(button and on_button))
        self.set_reveal_child(True)

    def clear(self) -> None:
        self.set_reveal_child(False)
        self._action = None

    def _on_button(self, *_a) -> None:
        action = self._action
        self.clear()
        if action is not None:
            action()

    def _on_close(self, *_a) -> None:
        self._dismissed = self._key
        self.clear()
