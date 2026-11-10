"""Short text on screen, the rest behind a (?) — shared by the kiwi apps.

The rule the user gave on 2026-11-11: no long texts in rows and groups; where
context helps, a small (?) button opens a popover with a few sentences and a link
to the app's page on kiwi-network.eu.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

DOCS = "https://kiwi-network.eu/docs/clients/"
PAGES = {
    "kiwi-proxy": "kiwi-proxy/",
    "kiwi-fox": "kiwi-fox/",
    "kiwi-custodia": "kiwi-custodia/",
    "providers": "providers/",
}


def docs_url(app: str = "", anchor: str = "") -> str:
    url = DOCS + PAGES.get(app, "")
    return f"{url}#{anchor}" if anchor else url


def info_button(text: str, *, app: str = "", anchor: str = "", link: bool = True) -> Gtk.MenuButton:
    """A flat (?) that opens `text` in a popover, with a link to the docs."""
    box = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL,
        spacing=10,
        margin_top=10,
        margin_bottom=10,
        margin_start=12,
        margin_end=12,
    )
    label = Gtk.Label(
        label=text, wrap=True, max_width_chars=44, xalign=0, selectable=False, use_markup=False
    )
    box.append(label)
    if link:
        more = Gtk.LinkButton(
            uri=docs_url(app, anchor), label="More in the docs", halign=Gtk.Align.START
        )
        more.add_css_class("flat")
        box.append(more)
    popover = Gtk.Popover(child=box)
    # A plain "?", not an icon: it looks the same in every icon theme (Adwaita's
    # question icon is a diamond that reads as a warning).
    mark = Gtk.Label(label="?")
    mark.add_css_class("heading")
    button = Gtk.MenuButton(
        child=mark,
        valign=Gtk.Align.CENTER,
        popover=popover,
        tooltip_text="What is this?",
    )
    button.add_css_class("flat")
    button.add_css_class("circular")
    button.update_property([Gtk.AccessibleProperty.LABEL], ["More about this"])
    return button


def explain(widget: Gtk.Widget, text: str, *, app: str = "", anchor: str = "", link: bool = True):
    """Put a (?) on a row (as a suffix, before its own) or a group (in its header)."""
    button = info_button(text, app=app, anchor=anchor, link=link)
    if isinstance(widget, Adw.PreferencesGroup):
        widget.set_header_suffix(button)
    elif isinstance(widget, Adw.ActionRow | Adw.ExpanderRow):
        widget.add_suffix(button)
    else:
        raise TypeError(f"no place for a (?) on {type(widget).__name__}")
    return button


def widen(page: Adw.PreferencesPage, width: int = 920) -> None:
    """A preferences page clamps its rows at 600 px; a window's list wants the
    room for two buttons and two lines of state."""
    child = page.get_first_child()
    stack = [child] if child else []
    while stack:
        widget = stack.pop()
        if isinstance(widget, Adw.Clamp):
            widget.set_maximum_size(width)
            widget.set_tightening_threshold(width - 200)
            return
        sub = widget.get_first_child()
        while sub is not None:
            stack.append(sub)
            sub = sub.get_next_sibling()
