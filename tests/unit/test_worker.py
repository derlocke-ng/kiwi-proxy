"""The worker's callbacks run once, whatever they return."""

from __future__ import annotations

import time

import pytest

gi = pytest.importorskip("gi")
gi.require_version("GLib", "2.0")
from gi.repository import GLib  # noqa: E402

from kiwi_proxy.ui import worker  # noqa: E402


def _spin(seconds: float) -> None:
    ctx = GLib.MainContext.default()
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        while ctx.pending():
            ctx.iteration(False)
        time.sleep(0.01)


def test_a_callback_that_returns_something_true_runs_once():
    # Kiwi Fox's engines page answered an install with a new worker's thread,
    # which GLib took for "call me again": it rebuilt itself forever.
    calls = []
    worker.run(lambda: 1, lambda v: (calls.append(v), "truthy")[1])
    worker.run(lambda: 1 / 0, None, lambda exc: (calls.append(type(exc).__name__), "truthy")[1])
    _spin(0.5)
    assert sorted(map(str, calls)) == ["1", "ZeroDivisionError"]
