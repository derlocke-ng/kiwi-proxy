"""Discover and load provider modules installed under paths.modules_dir().

A module is a directory holding a ``provider.py`` that exposes ``PROVIDER`` (a
Provider) and ``MANIFEST`` (a ProviderManifest). It is loaded by file path, not by
import name, so a module directory may start with a digit (``9proxy``) — which is
not a legal Python identifier and could never be ``import``ed normally.
"""

from __future__ import annotations

import importlib.util
import re

from .. import paths
from ..models import ProviderManifest
from .base import Provider, ProviderContext, ProviderError

_SYNTH_RE = re.compile(r"[^0-9a-zA-Z_]")
# A module name is a single path segment in a safe charset: no separators, no
# "..", so a name can never escape modules_dir() to load an arbitrary provider.py.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def valid_name(name: str) -> bool:
    return bool(name) and name != ".." and "/" not in name and bool(_NAME_RE.match(name))


def discover() -> list[str]:
    """Installed module names, each a directory under modules_dir() with a
    provider.py."""
    root = paths.modules_dir()
    if not root.exists():
        return []
    return sorted(
        d.name
        for d in root.iterdir()
        if d.is_dir() and (d / "provider.py").exists() and not d.name.startswith(".")
    )


def is_installed(name: str) -> bool:
    return valid_name(name) and (paths.module_dir(name) / "provider.py").exists()


def load(name: str) -> tuple[Provider, ProviderManifest]:
    """Import a module's provider.py and return its (PROVIDER, MANIFEST)."""
    if not valid_name(name):
        raise ProviderError(f"invalid provider module name {name!r}")
    path = paths.module_dir(name) / "provider.py"
    if not path.exists():
        raise ProviderError(f"provider module {name!r} is not installed ({path} missing)")
    synth = "kiwi_proxy_module_" + _SYNTH_RE.sub("_", name)
    spec = importlib.util.spec_from_file_location(synth, path)
    if spec is None or spec.loader is None:
        raise ProviderError(f"{name}: could not load {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise ProviderError(f"{name}: provider.py failed to import: {exc}") from exc

    provider = getattr(module, "PROVIDER", None)
    if provider is None:
        raise ProviderError(f"{name}: provider.py defines no PROVIDER")
    manifest = getattr(module, "MANIFEST", None) or getattr(provider, "manifest", None)
    if manifest is None:
        raise ProviderError(f"{name}: provider.py exposes no MANIFEST")
    if not isinstance(manifest, ProviderManifest):
        raise ProviderError(f"{name}: MANIFEST is not a ProviderManifest")
    if manifest.name != name:
        raise ProviderError(
            f"module directory {name!r} does not match manifest name {manifest.name!r}"
        )
    if not isinstance(provider, Provider):
        raise ProviderError(f"{name}: PROVIDER does not satisfy the Provider interface")
    return provider, manifest


def get_provider(name: str) -> Provider:
    return load(name)[0]


def manifest_of(name: str) -> ProviderManifest:
    return load(name)[1]


def context_for(name: str, manifest: ProviderManifest | None = None) -> ProviderContext:
    """Build the host-side context a provider is handed."""
    if manifest is None:
        manifest = manifest_of(name)
    image = manifest.image or paths.provider_image(name)
    state = paths.module_state_dir(name)
    state.mkdir(parents=True, exist_ok=True)
    return ProviderContext(
        name=name,
        module_dir=paths.module_dir(name),
        state_dir=state,
        network=paths.PROVIDERS_NETWORK,
        image=image,
        socks_port=manifest.socks_port,
    )


def manages(name: str | None) -> bool:
    """True when kiwi-proxy should manage this endpoint's provider lifecycle: the
    module is installed and runs its own container. A ``module`` tag for an
    uninstalled or remote-only provider is just a label on a plain SOCKS5 endpoint.
    """
    if not name or not is_installed(name):
        return False
    try:
        return manifest_of(name).runs_container
    except ProviderError:
        return False
