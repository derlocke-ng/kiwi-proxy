"""First-run setup: everything needed before an exit can come up.

Deliberately *not* done at install time — building images needs network at the
wrong moment and would make `kiwi install` look broken. kiwi-fox's own setup calls
`run()` too, so a browser user still runs one command.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Callable
from pathlib import Path

from . import dns, paths, podman, providers

IMAGES = ((paths.GATEWAY_IMAGE, "gateway"),)
SOURCE_LABEL = "kiwi-proxy.source"

Progress = Callable[[str], None]


class SetupError(RuntimeError):
    pass


def containers_dir() -> Path:
    """Where the Containerfiles live, in a checkout or an installed copy."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[2] / "containers", here.parents[1] / "containers"):
        if (candidate / "gateway" / "Containerfile").exists():
            return candidate
    raise SetupError("cannot find the containers/ directory next to the package")


def source_hash(name: str) -> str:
    """A fingerprint of everything an image is built from."""
    digest = hashlib.sha256()
    root = containers_dir() / name
    for path in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()[:16]


def image_state(image: str, name: str) -> str:
    """missing | stale | current. Stale: built from sources an update has since
    replaced — the app is new and the image is not."""
    if not podman.image_exists(image):
        return "missing"
    label = podman._run(
        ["image", "inspect", "--format", f'{{{{index .Labels "{SOURCE_LABEL}"}}}}', image],
        check=False,
    ).stdout.strip()
    return "current" if label == source_hash(name) else "stale"


def build_images(progress: Progress | None = None, force: bool = False) -> list[str]:
    root = containers_dir()
    built = []
    for image, name in IMAGES:
        if image_state(image, name) == "current" and not force:
            continue
        if progress:
            progress(f"Building the {name} image — this takes a minute…")
        proc = subprocess.run(  # noqa: S603
            [
                "podman",
                "build",
                "-t",
                image,
                "--label",
                f"{SOURCE_LABEL}={source_hash(name)}",
                "-f",
                str(root / name / "Containerfile"),
                str(root / name),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise SetupError(f"building {image} failed:\n{proc.stderr[-800:]}")
        built.append(image)
    return built


def run(progress: Progress | None = None) -> list[str]:
    """Idempotent: safe to run again at any time."""

    def say(message: str) -> None:
        if progress:
            progress(message)

    steps: list[str] = []
    paths.ensure_tree()
    if not podman.available():
        raise SetupError("podman is not installed")

    say("Building the gateway image…")
    built = build_images(progress)
    steps.append(f"images: {'built ' + ', '.join(built) if built else 'already present'}")

    say("Fetching DNS resolver stamps…")
    try:
        dns.sync_stamps()
        steps.append(f"dns: {len(dns.load_stamps())} resolver stamps")
    except Exception as exc:  # noqa: BLE001
        steps.append(f"dns stamps: failed ({exc})")

    say("Downloading the ad-block list…")
    try:
        dns.fetch_blocklist("oisd-big")
        merged = dns.merged_blocklist(["oisd-big"])
        count = sum(1 for _ in merged.open())
        steps.append(f"blocklist: {count} entries")
    except Exception as exc:  # noqa: BLE001
        steps.append(f"blocklist: failed ({exc})")

    modules = providers.discover()
    if modules:
        say("Preparing provider modules…")
        for name in modules:
            try:
                prov, manifest = providers.load(name)
                ctx = providers.context_for(name, manifest)
                prov.setup(ctx)
                steps.append(f"module {name}: image ready")
            except Exception as exc:  # noqa: BLE001 - one module must not fail setup
                steps.append(f"module {name}: setup failed ({exc})")

    say("Done.")
    return steps


def setup_module(name: str, progress: Progress | None = None) -> None:
    """Build/pull a single provider module's image. For `kiwi-proxy module setup`."""
    if not podman.available():
        raise SetupError("podman is not installed")
    if not providers.is_installed(name):
        raise SetupError(f"provider module {name!r} is not installed")
    prov, manifest = providers.load(name)
    ctx = providers.context_for(name, manifest)
    if progress:
        progress(f"Preparing provider module {name}…")
    prov.setup(ctx)
