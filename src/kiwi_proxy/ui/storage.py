"""The "Check and repair" item of each kiwi app's menu: podman's quick storage
check, and a repair that names every container it would remove before it does.

Shared by Kiwi Proxy, Kiwi Fox and Kiwi Custodia, like the snapshot pages."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from .. import storage  # noqa: E402
from . import worker  # noqa: E402

APP_TITLES = {
    "kiwi-proxy": "Kiwi Proxy",
    "kiwi-fox": "Kiwi Fox",
    "kiwi-custodia": "Kiwi Custodia",
    "kiwi-pentesting": "Kiwi Pentesting",
}


def _alert(parent: Gtk.Widget, heading: str, body: str) -> Adw.AlertDialog:
    dialog = Adw.AlertDialog(heading=heading, body=body)
    dialog.add_response("close", "Close")
    dialog.set_close_response("close")
    dialog.present(parent)
    return dialog


def _line(c: storage.Container) -> str:
    who = APP_TITLES.get(c.app or "", "not Kiwi's")
    return f"• {c.name} ({who})"


def check_and_repair(parent: Gtk.Widget, on_changed=None) -> None:
    """Check, show what is wrong, and repair on the user's word."""
    waiting = Adw.AlertDialog(
        heading="Checking Podman's storage…",
        body="podman system check --quick: every image, layer and container.",
    )
    waiting.add_response("close", "Close")
    waiting.set_close_response("close")
    waiting.present(parent)

    def done(report: storage.Report) -> None:
        waiting.close()
        show(parent, report, on_changed)

    def failed(exc: Exception) -> None:
        waiting.close()
        _alert(parent, "Could not check Podman's storage", str(exc))

    worker.run(storage.check, done, failed)


def _offer_old_images(parent: Gtk.Widget, on_changed=None) -> None:
    """Storage is fine: say so, and offer to remove Kiwi's images nothing uses."""

    def found(old: list[storage.Image]) -> None:
        if not old:
            _alert(parent, "Podman's storage is fine", "Nothing is damaged, nothing is left over.")
            return
        total = sum(i.size for i in old) / 1e6
        lines = [f"• {i.name.removeprefix('localhost/')} ({i.size / 1e6:.0f} MB)" for i in old]
        dialog = Adw.AlertDialog(
            heading="Podman's storage is fine",
            body="Nothing is damaged. These old Kiwi images are not used by anything "
            f"any more ({total:.0f} MB):\n" + "\n".join(lines),
        )
        dialog.add_response("cancel", "Keep")
        dialog.add_response("remove", "Remove")
        dialog.set_response_appearance("remove", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_close_response("cancel")

        def on_response(_d, response: str) -> None:
            if response != "remove":
                return
            worker.run(
                lambda: storage.remove_images([i.name for i in old]),
                lambda gone: (
                    _alert(parent, "Removed", f"{len(gone)} of {len(old)} old images."),
                    on_changed() if on_changed else None,
                ),
                lambda exc: _alert(parent, "Could not remove", str(exc)),
            )

        dialog.connect("response", on_response)
        dialog.present(parent)

    worker.run(storage.old_images, found, lambda _exc: found([]))


def show(parent: Gtk.Widget, report: storage.Report, on_changed=None) -> None:
    if report.error:
        _alert(parent, "Could not check Podman's storage", report.error)
        return
    if report.ok:
        _offer_old_images(parent, on_changed)
        return
    ours, others = report.ours, report.others
    body: list[str] = []
    if ours:
        body.append("These containers cannot be used any more; Repair removes them:")
        body += [_line(c) for c in ours]
        if any(c.app == "kiwi-custodia" for c in ours):
            body.append(
                "A box keeps its home and what its last stop committed; what was installed "
                "in it since then is lost."
            )
        body.append("Kiwi makes the others again the next time they are started.")
    if others:
        body.append("")
        body.append("These are not Kiwi's. They are only removed if you say so:")
        body += [_line(c) for c in others]
    if report.layers and not report.broken:
        body.append(
            f"Podman reports {len(report.layers)} damaged layer(s) no container uses; "
            "Repair lets podman remove them."
        )
    dialog = Adw.AlertDialog(heading="Podman's storage is damaged", body="\n".join(body))
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("repair", "Repair")
    dialog.set_response_appearance("repair", Adw.ResponseAppearance.DESTRUCTIVE)
    if others:
        dialog.add_response("all", "Repair, theirs too")
        dialog.set_response_appearance("all", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_close_response("cancel")

    def on_response(_d, response: str) -> None:
        if response == "cancel":
            return
        names = [c.id for c in ours] + ([c.id for c in others] if response == "all" else [])

        def repaired(after: storage.Report) -> None:
            if on_changed:
                on_changed()
            if after.ok:
                _alert(parent, "Repaired", "Podman's storage is fine again.")
            else:
                show(parent, after, on_changed)

        worker.run(
            lambda: storage.repair(report, names),
            repaired,
            lambda exc: _alert(parent, "Could not repair", str(exc)),
        )

    dialog.connect("response", on_response)
    dialog.present(parent)
