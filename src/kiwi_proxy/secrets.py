"""Where passwords live. Never in JSON, logs or container env.

The Secret Service via ``secret-tool`` on a desktop. A machine with no Secret
Service — a headless node, a server reached over SSH — gets 0600 files under
``config_dir()/secrets`` instead; ``KIWI_PROXY_SECRETS=keyring|file`` forces one.

Each secret is keyed on an exit id and a kind: ``endpoint`` (the upstream's
password) or ``expose`` (the password the host listener demands).
"""

from __future__ import annotations

import os
import shutil
import subprocess

from . import paths

KINDS = ("endpoint", "expose")


def backend() -> str:
    forced = os.environ.get("KIWI_PROXY_SECRETS", "").strip().lower()
    if forced in ("keyring", "file"):
        return forced
    return "keyring" if shutil.which("secret-tool") else "file"


def available() -> bool:
    """There is always somewhere to put a secret; this says whether it is the
    keyring (for doctor)."""
    return backend() == "keyring"


def _attrs(exit_id: str, kind: str) -> list[str]:
    return ["application", paths.APP, "exit", exit_id, "kind", kind]


def _file(exit_id: str, kind: str):
    return paths.secrets_dir() / f"{exit_id}.{kind}"


def store(exit_id: str, password: str, *, kind: str = "endpoint", label: str | None = None) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown secret kind {kind!r}")
    if backend() == "file":
        path = _file(exit_id, kind)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(password)
        return
    subprocess.run(  # noqa: S603
        [
            "secret-tool",
            "store",
            "--label",
            label or f"{paths.APP} {kind} {exit_id[:12]}",
            *_attrs(exit_id, kind),
        ],
        input=password,
        text=True,
        check=True,
        capture_output=True,
    )


def lookup(exit_id: str, *, kind: str = "endpoint") -> str | None:
    if backend() == "file":
        path = _file(exit_id, kind)
        return (path.read_text() or None) if path.exists() else None
    proc = subprocess.run(  # noqa: S603
        ["secret-tool", "lookup", *_attrs(exit_id, kind)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 and proc.stdout else None


def clear(exit_id: str, *, kind: str | None = None) -> None:
    for k in [kind] if kind else KINDS:
        _file(exit_id, k).unlink(missing_ok=True)
        if shutil.which("secret-tool"):
            subprocess.run(  # noqa: S603
                ["secret-tool", "clear", *_attrs(exit_id, k)], check=False, capture_output=True
            )
