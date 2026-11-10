"""What can go wrong with snapshots, as exceptions a window or the CLI can word."""

from __future__ import annotations


class SnapshotError(RuntimeError):
    """Anything that stops a snapshot or a restore; the message is for the user."""


class NotSetUp(SnapshotError):
    """No snapshot folder is chosen on this device."""


class Locked(SnapshotError):
    """The folder is chosen, but this device does not hold its passphrase."""


class BadPassphrase(SnapshotError):
    """The passphrase does not open the folder."""


class NotReady(SnapshotError):
    """The snapshot is listed, but its data has not fully arrived (still syncing)."""
