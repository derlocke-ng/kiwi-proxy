"""Podman's storage, checked and repaired, for all three kiwi apps.

Two things, measured on the dev VM (2026-11-10):

- **Leftovers.** A hard reset while containers are being created leaves them
  "created" or "exited" (some dated 292 years ago); `podman run --replace`
  recovers each one, and nothing hangs. Each app removes its own leftovers when it
  starts (:func:`leftovers`, :func:`remove`).
- **Damage.** A container whose storage folder is gone cannot start, be inspected
  or be committed; `podman rm -f` still removes it. `podman system check --quick`
  finds it in 0.07 s and names its layer. The full check takes 13 s and reported
  1142 "layer content modified" lines (mtimes only) on healthy images, so only the
  quick one is used. Its `--repair` acts on the whole store, so :func:`check`
  names every broken container, kiwi's or not, before anything is removed.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from . import paths, podman

# States a container is left in by a crash, a reset or a stop nobody finished.
LEFTOVER_STATES = ("created", "exited", "dead", "stopping", "configured", "initialized")
_LAYER_RE = re.compile(r"\b([0-9a-f]{64})\b")
_BROKEN_HINTS = ("no such file or directory", "graph driver", "layer not known", "mounting storage")


@dataclass
class Container:
    id: str
    name: str
    state: str
    labels: dict[str, str] = field(default_factory=dict)
    created: float = 0.0  # unix time

    @property
    def app(self) -> str | None:
        """Which kiwi app made it, or None for a container that is not kiwi's."""
        lab = self.labels
        if lab.get("app", "").startswith("kiwi-"):
            return lab["app"]
        if paths.ROLE_LABEL in lab:
            return "kiwi-proxy"
        if any(k.startswith(("kiwi-fox.", "kiwi-custodia.")) for k in lab):
            return next(
                k.split(".")[0] for k in lab if k.startswith(("kiwi-fox.", "kiwi-custodia."))
            )
        return None


def containers() -> list[Container]:
    """Every container podman has, kiwi's or not, with its state and labels."""
    proc = podman._run(["ps", "--all", "--format", "json"], check=False, timeout=60)
    out = []
    for c in json.loads(proc.stdout or "[]") if proc.returncode == 0 else []:
        names = c.get("Names") or [c.get("Id", "")[:12]]
        out.append(
            Container(
                id=c.get("Id", ""),
                name=names[0],
                state=(c.get("State") or "").lower(),
                labels=c.get("Labels") or {},
                created=float(c.get("Created") or 0),
            )
        )
    return out


def leftovers(
    app: str, *, everything: list[Container] | None = None, min_age: float = 120.0
) -> list[Container]:
    """`app`'s own containers that are not running and never will again by
    themselves: what a crash, a reset or an unfinished stop left. One made in the
    last `min_age` seconds is left alone: another app may be starting it."""
    now = time.time()
    return [
        c
        for c in (everything if everything is not None else containers())
        if c.app == app and c.state in LEFTOVER_STATES and now - c.created >= min_age
    ]


def remove_leftovers(app: str) -> list[str]:
    """Repair on start: remove `app`'s leftovers; the names that went."""
    if not podman.available():
        return []
    return remove([c.name for c in leftovers(app)])


def remove(names: list[str]) -> list[str]:
    """`podman rm -f` each; the ones that went."""
    gone = []
    for name in names:
        if podman._run(["rm", "--force", name], check=False, timeout=60).returncode == 0:
            gone.append(name)
    return gone


def _readable(c: Container) -> bool:
    proc = podman._run(
        ["container", "inspect", "--format", "{{.GraphDriver.Name}}", c.id], check=False, timeout=30
    )
    if proc.returncode == 0:
        return True
    err = proc.stderr.lower()
    return not any(h in err for h in _BROKEN_HINTS)


@dataclass
class Report:
    ok: bool
    output: str  # what podman said, for the details
    broken: list[Container] = field(default_factory=list)  # containers whose storage is damaged
    layers: list[str] = field(default_factory=list)  # damaged layers podman named
    error: str = ""  # the check itself could not run

    @property
    def ours(self) -> list[Container]:
        return [c for c in self.broken if c.app]

    @property
    def others(self) -> list[Container]:
        return [c for c in self.broken if not c.app]


def check(timeout: int = 300) -> Report:
    """`podman system check --quick`, and which containers the damage belongs to."""
    if not podman.available():
        return Report(ok=False, output="", error="podman is not installed")
    proc = podman._run(["system", "check", "--quick"], check=False, timeout=timeout)
    output = (proc.stdout + proc.stderr).strip()
    damaged = "damage detected" in output.lower() or "damaged" in output.lower()
    if proc.returncode != 0 and not damaged:
        return Report(
            ok=False, output=output, error=output.splitlines()[-1] if output else "failed"
        )
    if not damaged:
        return Report(ok=True, output=output)
    layers = sorted(set(_LAYER_RE.findall(output)))
    broken = [c for c in containers() if not _readable(c)]
    return Report(ok=False, output=output, broken=broken, layers=layers)


def repair(report: Report, names: list[str]) -> Report:
    """Remove the named broken containers, let podman repair what is left of the
    damage (`--repair`: damaged images and layers no container uses), and check
    again. Containers not named stay, and so does damage that belongs to them."""
    remove(names)
    if report.layers or not report.broken:
        podman._run(["system", "check", "--quick", "--repair"], check=False, timeout=600)
    return check()


# ---------------------------------------------------------------- old images
# Images Kiwi built once and nothing asks for any more: an app's image from
# before a rename (kiwi-fox/gateway, from before kiwi-proxy existed), a module's
# adapter the module no longer has (vpn-adapter), a tag kept by hand. Only images
# under Kiwi's own names are looked at; untagged ones cannot be told from the
# user's own and are left alone. An image a container still uses is never listed.
KIWI_REPOS = ("localhost/kiwi-proxy/", "localhost/kiwi-fox/", "localhost/kiwi-custodia/")


@dataclass(frozen=True)
class Image:
    name: str  # localhost/kiwi-fox/browser:before-fonts
    id: str
    size: int


def wanted_images() -> set[str]:
    """Every image name the installed Kiwi apps build and start from."""
    from . import providers

    want = {
        f"localhost/{paths.GATEWAY_IMAGE}",
        "localhost/kiwi-fox/browser:latest",
        "localhost/kiwi-custodia/tunnel:latest",
    }
    for name in providers.discover():
        try:
            prov, manifest = providers.load(name)
            ctx = providers.context_for(name, manifest)
        except Exception:  # noqa: BLE001 - a module that does not load keeps its images
            want |= {
                f"localhost/{paths.provider_image(name)}",
                f"localhost/{paths.provider_image(name + '-adapter')}",
            }
            continue
        want.add(_local(ctx.image))
        if hasattr(prov, "adapter_spec") and manifest.joins != "tunnel":
            want.add(_local(ctx.adapter_image))
    return want


def _local(image: str) -> str:
    """As `podman images` names a locally built image; a registry's stays as it is."""
    return image if image.split("/")[0].count(".") else f"localhost/{image}"


def old_images(*, wanted: set[str] | None = None) -> list[Image]:
    """Kiwi's own images that nothing wants and no container uses. A Kiwi
    Custodia box's image (box-…) is the box's contents and is never one."""
    if not podman.available():
        return []
    want = wanted if wanted is not None else wanted_images()
    used = {
        c.get("ImageID", "")
        for c in json.loads(
            podman._run(["ps", "--all", "--format", "json"], check=False, timeout=60).stdout or "[]"
        )
    }
    proc = podman._run(["images", "--format", "json"], check=False, timeout=60)
    out = []
    for img in json.loads(proc.stdout or "[]") if proc.returncode == 0 else []:
        if img.get("Id") in used:
            continue
        for name in img.get("Names") or []:
            if not name.startswith(KIWI_REPOS) or name in want:
                continue
            if name.startswith("localhost/kiwi-custodia/box-"):
                continue
            out.append(Image(name=name, id=img.get("Id", ""), size=int(img.get("Size") or 0)))
    return sorted(out, key=lambda i: i.name)


def remove_images(names: list[str]) -> list[str]:
    """`podman rmi` each (never forced: one in use stays); the ones that went."""
    gone = []
    for name in names:
        if podman._run(["rmi", name], check=False, timeout=120).returncode == 0:
            gone.append(name)
    return gone
