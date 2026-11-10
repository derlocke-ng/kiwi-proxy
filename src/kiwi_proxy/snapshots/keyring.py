"""Where this device keeps the snapshot passphrase once it was entered.

The same rule as every other kiwi-proxy password (see ``kiwi_proxy.secrets``): the
Secret Service (GNOME keyring) through ``secret-tool`` on a desktop; a 0600 file
under the config directory only on a machine that has no Secret Service. The entry
is keyed on the folder's id, so Kiwi Fox and Kiwi Custodia find the same one.
"""

from __future__ import annotations

import os
import subprocess

from .. import paths, secrets
from .errors import SnapshotError

APPLICATION = "kiwi-snapshots"


def _attrs(folder_id: str) -> list[str]:
    return ["application", APPLICATION, "folder", folder_id]


def _file(folder_id: str):
    return paths.secrets_dir() / f"snapshots-{folder_id}"


def backend() -> str:
    return secrets.backend()


def store(folder_id: str, passphrase: str, *, label: str) -> None:
    if backend() == "file":
        path = _file(folder_id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(passphrase)
        return
    proc = subprocess.run(  # noqa: S603
        ["secret-tool", "store", "--label", label, *_attrs(folder_id)],
        input=passphrase,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SnapshotError(
            "the keyring would not keep the passphrase"
            + (f": {proc.stderr.strip()}" if proc.stderr.strip() else "")
        )


def lookup(folder_id: str) -> str | None:
    if backend() == "file":
        path = _file(folder_id)
        return (path.read_text() or None) if path.exists() else None
    proc = subprocess.run(  # noqa: S603
        ["secret-tool", "lookup", *_attrs(folder_id)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 and proc.stdout else None


def clear(folder_id: str) -> None:
    _file(folder_id).unlink(missing_ok=True)
    if backend() == "keyring":
        subprocess.run(  # noqa: S603
            ["secret-tool", "clear", *_attrs(folder_id)], capture_output=True, check=False
        )
