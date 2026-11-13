"""Run blocking work off the main loop.

Podman calls, provider start-up and exit measurements all block for seconds. The
GTK main loop must never wait on them, so everything goes through here and comes
back via GLib.idle_add.
"""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable
from typing import Any

from gi.repository import GLib


def _once(callback: Callable[[Any], Any], value: Any) -> bool:
    """Call back once. GLib calls an idle callback again for as long as it returns
    something true, and a callback that returned what it last did (a new worker's
    thread, a tuple of setter results) ran forever: Kiwi Fox's engines page
    rebuilt itself in a loop after an install until the app was restarted."""
    callback(value)
    return GLib.SOURCE_REMOVE


def run(
    work: Callable[[], Any],
    on_done: Callable[[Any], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
) -> threading.Thread:
    def target() -> None:
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI, not swallowed
            traceback.print_exc()
            if on_error:
                GLib.idle_add(_once, on_error, exc)
            return
        if on_done:
            GLib.idle_add(_once, on_done, result)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread
