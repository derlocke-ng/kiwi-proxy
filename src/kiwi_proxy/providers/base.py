"""The provider contract: a module turns some upstream into a ready SOCKS5 exit.

Every provider module (tor, vpn, 9proxy, mysterium) adapts its upstream — the Tor
network, a VPN tunnel, a residential-proxy account, a Mysterium node — into plain
SOCKS5 and exposes nothing else. That is the load-bearing network decision (see
docs/decisions.md, "Every provider exposes SOCKS5 and nothing else"): the gateway,
forwarder, firewall rule and DNS design stay single-shaped, and adapting is the
module's job.

A local provider runs its own container with its own exit to the internet, on the
shared ``kf-providers`` bridge. It cannot share the gateway's network namespace —
the gateway default-drops everything but one destination, which would strand the
provider's own upstream — so the two meet on that bridge, and the gateway permits
exactly the provider's address on it. Plain, already-remote SOCKS5 endpoints never
touch any of this; those gateways stay on pasta.

``Provider`` is the interface kiwi-proxy depends on. ``ContainerProvider`` implements
the whole container lifecycle generically, so a plugin only declares its manifest,
its container spec, and its leases. Plugins live in their own repositories and
import ``ContainerProvider`` from here (``kiwi_proxy.providers.base``; it was
``kiwi_fox.core.providers.base`` before the split); they are discovered under
``paths.modules_dir()`` by the loader.

The lifecycle labels every container it starts with ``kiwi-proxy.role`` and
``kiwi-proxy.module`` itself, so a plugin's own labels are optional.
"""

from __future__ import annotations

import hashlib
import inspect
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from .. import countries, paths, podman
from ..models import ContainerSpec, Endpoint, Lease, ProviderManifest, ProviderStatus


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderContext:
    """Everything host-side a provider is handed, so it never reaches into kiwi-proxy
    internals directly. One context per module."""

    name: str
    module_dir: Path  # where the module is installed (modules_dir()/<name>)
    state_dir: Path  # per-module writable state (leases, caches)
    network: str  # the shared providers bridge
    image: str  # the provider image name (kiwi-proxy/<name>:latest)
    socks_port: int

    def container_name(self, lease: str | None = None) -> str:
        return paths.provider_container_name(self.name, lease)

    def static_ip(self, lease: str | None = None) -> str:
        """The provider's deterministic address on the providers bridge."""
        return paths.provider_static_ip(self.name, lease)

    def adapter_name(self, lease: str | None = None) -> str:
        """Name of the SOCKS5 adapter sidecar, for a tunnel provider."""
        return paths.provider_container_name(f"{self.name}-adapter", lease)

    @property
    def adapter_image(self) -> str:
        """The adapter image, always built locally (alpine + microsocks), separate
        from a tunnel image that may be pulled."""
        return paths.provider_image(f"{self.name}-adapter")

    def containerfile(self, subdir: str = "") -> Path:
        base = self.module_dir / "containers"
        return (base / subdir / "Containerfile") if subdir else (base / "Containerfile")

    # ------------------------------------------------------------- module secrets
    # For a module that wants a module-level value (not per-exit) as a podman
    # secret mounted into its container. The first-party modules keep theirs as
    # files in ctx.state_dir instead. Per-exit credentials always go through the
    # gateway forwarder, untouched.
    def secret_name(self, key: str) -> str:
        return f"{paths.PREFIX}-mod-{self.name}-{key}"

    def set_secret(self, key: str, value: str) -> None:
        podman.secret_set(self.secret_name(key), value)

    def secret_mount(self, key: str, target: str) -> tuple[str, str]:
        return (self.secret_name(key), target)


@dataclass(frozen=True)
class Setting:
    """One thing a module needs from the user before it can run — a keystore
    file, a passphrase, an account token. The app and `kiwi-proxy module config`
    ask for them the same way; the module's ``configure`` takes the values."""

    key: str
    title: str
    # "choice" (an exit option only): picked from a list the module gives,
    # `option_choices(ctx, key, country) -> list[Lease]`.
    kind: Literal["file", "password", "text", "choice"] = "text"
    help: str = ""
    required: bool = True


@dataclass(frozen=True)
class Node:
    """One exit relay a module can be held to (Tor): its fingerprint, nickname,
    country, the network it is in, and its advertised speed in bytes a second."""

    fingerprint: str
    name: str
    country: str
    operator: str = ""
    speed: int = 0


@dataclass(frozen=True)
class Country:
    """A country a module can exit in: the code, its name, and how many exits the
    module has there when it knows (Tor relays, Mysterium providers)."""

    code: str
    name: str
    count: int | None = None

    @property
    def label(self) -> str:
        return countries.label(self.code, self.count)


def countries_for(prov: Provider, ctx: ProviderContext) -> list[Country]:
    """The countries a module offers, by name — the module's own list, or every
    country there is when it has none to give (and for modules from before the
    hook). A module's list is sorted by name; its own order is not trusted."""
    found: list[Country] = []
    if hasattr(prov, "countries"):
        found = list(prov.countries(ctx))
    if not found:
        found = [Country(code, name) for code, name in countries.NAMES.items()]
    return sorted(found, key=lambda c: c.name.lower())


def leases_for(prov: Provider, ctx: ProviderContext, country: str | None = None) -> list[Lease]:
    """A module's selectable exits, for one country when the module can filter.
    Modules from before the ``country`` parameter are called without it."""
    try:
        takes_country = "country" in inspect.signature(prov.leases).parameters
    except (TypeError, ValueError):
        takes_country = False
    if country and takes_country:
        return prov.leases(ctx, country=country)
    return prov.leases(ctx)


@runtime_checkable
class Provider(Protocol):
    """What kiwi-proxy calls. A plugin usually gets all of this from
    ``ContainerProvider`` and overrides only ``container_spec`` and ``leases``."""

    manifest: ProviderManifest
    lease_noun: str  # "node", "server", "port"… — see ContainerProvider

    @property
    def name(self) -> str: ...

    def requirements(self) -> list[str]: ...

    def setup(self, ctx: ProviderContext) -> None: ...

    def leases(self, ctx: ProviderContext) -> list[Lease]: ...

    def countries(self, ctx: ProviderContext) -> list[Country]: ...

    def settings(self, ctx: ProviderContext) -> list[Setting]: ...

    def configure(self, ctx: ProviderContext, values: dict[str, str]) -> list[str]: ...

    def configured(self, ctx: ProviderContext) -> str | None: ...

    def up(
        self, ctx: ProviderContext, *, lease: str | None = None, country: str | None = None
    ) -> Endpoint: ...

    def down(self, ctx: ProviderContext, *, lease: str | None = None) -> None: ...

    def status(self, ctx: ProviderContext) -> ProviderStatus: ...


SOURCE_LABEL = "kiwi-proxy.source"


def source_hash(directory: Path) -> str:
    """What a module image is built from: every file under its containers folder,
    by path and content. A changed entrypoint changes it."""
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(directory)).encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()[:16]


class ContainerProvider:
    """Base class for a provider that runs a container exposing SOCKS5 on the
    providers bridge. Subclasses declare ``manifest`` and implement
    ``container_spec`` (and usually ``leases``); everything else is generic.
    """

    manifest: ProviderManifest

    # How long to wait for a freshly started provider container to come up and
    # get an address on the bridge. VPN handshakes and Tor bootstraps are slow.
    ready_timeout: float = 90.0

    # What this module calls one of its leases, for the app and the CLI: a
    # Mysterium "node", a VPN "server", a 9proxy "port". Read with getattr, so an
    # older module without it is an "exit".
    lease_noun = "exit"

    @property
    def name(self) -> str:
        return self.manifest.name

    def requirements(self) -> list[str]:
        return list(self.manifest.requires)

    # --------------------------------------------------------------- spec (abstract)
    def container_spec(
        self, ctx: ProviderContext, *, lease: str | None = None, country: str | None = None
    ) -> ContainerSpec:
        raise NotImplementedError(f"{self.name}: container_spec must be implemented")

    def leases(self, ctx: ProviderContext, *, country: str | None = None) -> list[Lease]:  # noqa: ARG002
        """The exits a module can pin, for one country when it can filter."""
        return []

    def countries(self, ctx: ProviderContext) -> list[Country]:  # noqa: ARG002
        """Where the module can exit, when it knows; empty means "ask for any
        country" and the app offers the whole table (kiwi_proxy.countries)."""
        return []

    # ------------------------------------------------------------------ settings
    def settings(self, ctx: ProviderContext) -> list[Setting]:  # noqa: ARG002
        """What the user has to provide before the module can run; none by default."""
        return []

    def configure(self, ctx: ProviderContext, values: dict[str, str]) -> list[str]:  # noqa: ARG002
        """Take the values for ``settings`` (file paths, passwords, text) and keep
        them in the module's state (and podman secrets); returns lines worth
        showing. A module without settings refuses."""
        raise ProviderError(f"{self.name}: nothing to configure")

    def configured(self, ctx: ProviderContext) -> str | None:  # noqa: ARG002
        """One line on what is configured — "identity 0x12…ab" — or None."""
        return None

    # --------------------------------------------------------------------- setup
    def setup(self, ctx: ProviderContext) -> None:
        """Build the provider image from the module's Containerfile, or pull it
        when the manifest names a remote image. Idempotent."""
        cf = ctx.containerfile()
        if cf.exists():
            podman.build(
                ctx.image,
                str(cf),
                str(cf.parent),
                labels={
                    "app": paths.APP,
                    paths.MODULE_LABEL: self.name,
                    SOURCE_LABEL: source_hash(cf.parent),
                },
            )
            return
        if self.manifest.image and "/" in self.manifest.image:
            podman.pull(self.manifest.image)
            return
        raise ProviderError(
            f"{self.name}: no Containerfile at {cf} and no pullable image in the manifest"
        )

    # ------------------------------------------------------------------- lifecycle
    def up(
        self,
        ctx: ProviderContext,
        *,
        lease: str | None = None,
        country: str | None = None,
        selection=None,
    ) -> Endpoint:
        """Bring the provider up (idempotent) and return its live SOCKS5 endpoint.

        The host is the container's current address on the bridge, resolved every
        time because a restart can change it; the gateway needs a literal address.
        """
        if not podman.available():
            raise ProviderError("podman not found")
        podman.network_ensure(
            ctx.network, subnet=paths.PROVIDERS_SUBNET, gateway=paths.PROVIDERS_GATEWAY_IP
        )
        # A selection (kiwi_proxy.selection) only for a module that takes one: an
        # older module's container_spec has no such argument.
        extra = {"selection": selection} if selection is not None else {}
        spec = self.container_spec(ctx, lease=lease, country=country, **extra)
        if spec.network != ctx.network:
            raise ProviderError(
                f"{self.name}: container_spec must attach to {ctx.network!r}, got {spec.network!r}"
            )
        # A deterministic address so the gateway's firewall pin survives a restart,
        # and a restart policy so an out-of-band crash recovers in place on it.
        spec.ip = ctx.static_ip(lease)
        spec.restart = spec.restart or "on-failure"
        _label(spec, self.name, lease, role="provider")
        if not podman.is_running(spec.name):
            self._ensure_current_image(ctx)
            podman.start(spec)
        try:
            ip = self._await_ready(ctx, spec.name)
        except ProviderError:
            # Not left running (and, with on-failure, restarting) with no exit
            # able to use it; the error says what its log said.
            self.down(ctx, lease=lease)
            raise
        return Endpoint(
            host=ip,
            port=self.manifest.socks_port,
            username=None,  # per-exit isolation/account creds are set when the gateway comes up
            has_password=False,
            module=self.name,
            lease=lease,
            country=country,
        )

    def _ensure_current_image(self, ctx: ProviderContext) -> None:
        """Rebuild the module's image when the module was updated since it was
        built: a container from an older image would ignore what a newer module
        asks of it (a Tor image from before 0.4 ignores the Only and Never lists
        and exits anywhere). A module with its own setup, or a pulled image, is
        left alone. A rebuild that fails stops the start: never a stale image."""
        cf = ctx.containerfile()
        if not cf.exists() or type(self).setup is not ContainerProvider.setup:
            return
        proc = podman._run(
            ["image", "inspect", "--format", f'{{{{index .Labels "{SOURCE_LABEL}"}}}}', ctx.image],
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip() == source_hash(cf.parent):
            return
        try:
            self.setup(ctx)
        except Exception as exc:  # noqa: BLE001 - a build, a network
            raise ProviderError(
                f"{self.name}: its image is older than the module and could not be rebuilt "
                f"({exc}); `kiwi-proxy module setup {self.name}`"
            ) from exc

    def _await_ready(self, ctx: ProviderContext, container: str) -> str:
        deadline = time.monotonic() + self.ready_timeout
        last = ""
        while time.monotonic() < deadline:
            if not podman.is_running(container):
                raise ProviderError(
                    f"{self.name}: provider container exited during start:"
                    + _log_tail(container, 20, getattr(self, "log_marker", None))
                )
            ip = podman.container_ip(container, ctx.network)
            if ip and self.ready(ctx, container):
                return ip
            last = ip or last
            time.sleep(0.5)
        raise ProviderError(
            f"{self.name}: provider did not become ready within {self.ready_timeout:.0f}s"
            + (f" (address {last})" if last else "")
            + _log_tail(container, marker=getattr(self, "log_marker", None))
        )

    def ready(self, ctx: ProviderContext, container: str) -> bool:  # noqa: ARG002
        """True when the SOCKS5 listener is accepting connections. The default
        trusts a running container; providers with a slow handshake (a VPN tunnel,
        a Tor bootstrap) should override to probe the port."""
        return True

    def down(self, ctx: ProviderContext, *, lease: str | None = None) -> None:
        podman.rm(ctx.container_name(lease))

    def status(self, ctx: ProviderContext) -> ProviderStatus:
        running = [
            c.get("Names", [""])[0]
            for c in podman.ps()
            if (c.get("Labels") or {}).get(paths.MODULE_LABEL) == self.name
            and c.get("State") == "running"
        ]
        return ProviderStatus(
            name=self.name,
            installed=True,
            image_present=podman.image_exists(ctx.image),
            running=bool(running),
            containers=running,
            leases=[lease.id for lease in _safe_leases(self, ctx)],
        )


class TunnelProvider(ContainerProvider):
    """A provider whose upstream is a tunnel that does not speak SOCKS5 itself — a
    VPN via gluetun, a Mysterium node. It runs two containers: the tunnel on the
    providers bridge, and a tiny microsocks adapter sharing the tunnel's network
    namespace, so the adapter's SOCKS5 rides the tunnel while being reachable on the
    bridge at the tunnel's own address. Adapting a tunnel into plain SOCKS5 is
    exactly the module's job.

    A subclass implements ``tunnel_spec`` (the tunnel container) and usually
    ``tunnel_ready`` (so the exit is live before the window opens). The adapter and
    the two-container lifecycle are generic.
    """

    def tunnel_spec(
        self, ctx: ProviderContext, *, lease: str | None = None, country: str | None = None
    ) -> ContainerSpec:
        raise NotImplementedError(f"{self.name}: tunnel_spec must be implemented")

    # The tunnel is the primary container for status/leases purposes.
    def container_spec(
        self, ctx: ProviderContext, *, lease: str | None = None, country: str | None = None
    ) -> ContainerSpec:
        return self.tunnel_spec(ctx, lease=lease, country=country)

    def adapter_spec(
        self, ctx: ProviderContext, tunnel: str, *, lease: str | None = None
    ) -> ContainerSpec:
        return ContainerSpec(
            name=ctx.adapter_name(lease),
            image=ctx.adapter_image,
            # Share the tunnel's netns: the adapter binds the tunnel's bridge
            # address and its own egress is the tunnel's default route.
            network=f"container:{tunnel}",
            args=[str(self.manifest.socks_port)],
            cap_drop=["all"],
            security_opt=["no-new-privileges"],
            labels={paths.MODULE_LABEL: self.name, paths.ROLE_LABEL: "adapter"},
        )

    def tunnel_ready(self, ctx: ProviderContext, container: str) -> bool:  # noqa: ARG002
        return True

    def up(
        self, ctx: ProviderContext, *, lease: str | None = None, country: str | None = None
    ) -> Endpoint:
        if not podman.available():
            raise ProviderError("podman not found")
        podman.network_ensure(
            ctx.network, subnet=paths.PROVIDERS_SUBNET, gateway=paths.PROVIDERS_GATEWAY_IP
        )
        tunnel = self.tunnel_spec(ctx, lease=lease, country=country)
        if tunnel.network != ctx.network:
            raise ProviderError(
                f"{self.name}: tunnel_spec must attach to {ctx.network!r}, got {tunnel.network!r}"
            )
        tunnel.ip = ctx.static_ip(lease)
        # No restart policy for a tunnel: its adapter joined the netns of *this*
        # container, and a podman restart gives the tunnel a new one with the
        # adapter left behind in the old — an exit that looks up and answers
        # nothing. A tunnel that dies is restarted together with its adapter by
        # gateway.heal(), behind the gateway that stays.
        tunnel.restart = None
        _label(tunnel, self.name, lease, role="tunnel")
        if not podman.is_running(tunnel.name):
            # The adapter joins the tunnel's netns (--network container:), which
            # makes the tunnel a dependent container: podman refuses to replace it
            # while the adapter exists. Remove a stale adapter first, exactly as the
            # gateway.up removes its members before replacing a gateway.
            podman.rm(ctx.adapter_name(lease))
            podman.start(tunnel)
        try:
            ip = self._await_tunnel(ctx, tunnel.name)
        except ProviderError:
            # A tunnel that never came up is not left running (and restarting);
            # the error carries what its log said.
            self.down(ctx, lease=lease)
            raise
        if self.manifest.joins == "tunnel":
            # The gateway joins the tunnel itself: no SOCKS5 adapter. The address
            # is only for status; the gateway reaches nothing by it.
            return Endpoint(
                host=ip,
                port=0,
                username=None,
                has_password=False,
                module=self.name,
                lease=lease,
                country=country,
            )
        adapter = self.adapter_spec(ctx, tunnel.name, lease=lease)
        _label(adapter, self.name, lease, role="adapter")
        if not podman.is_running(adapter.name):
            podman.start(adapter)
        if not podman.is_running(adapter.name):
            raise ProviderError(
                f"{self.name}: SOCKS5 adapter failed to start:\n" + podman.logs(adapter.name)
            )
        return Endpoint(
            host=ip,
            port=self.manifest.socks_port,
            username=None,
            has_password=False,
            module=self.name,
            lease=lease,
            country=country,
        )

    def _await_tunnel(self, ctx: ProviderContext, container: str) -> str:
        deadline = time.monotonic() + self.ready_timeout
        last = ""
        while time.monotonic() < deadline:
            if not podman.is_running(container):
                raise ProviderError(
                    f"{self.name}: tunnel container exited during start:"
                    + _log_tail(container, 20, getattr(self, "log_marker", None))
                )
            ip = podman.container_ip(container, ctx.network)
            if ip and self.tunnel_ready(ctx, container):
                return ip
            last = ip or last
            time.sleep(0.5)
        raise ProviderError(
            f"{self.name}: tunnel did not come up within {self.ready_timeout:.0f}s"
            + (f" (address {last})" if last else "")
            + _log_tail(container, marker=getattr(self, "log_marker", None))
        )

    def down(self, ctx: ProviderContext, *, lease: str | None = None) -> None:
        # Adapter first: it depends on the tunnel's netns, so podman refuses to
        # remove the tunnel while the adapter joins it.
        podman.rm(ctx.adapter_name(lease))
        podman.rm(ctx.container_name(lease))

    def setup(self, ctx: ProviderContext) -> None:
        if self.manifest.image and "/" in self.manifest.image:
            podman.pull(self.manifest.image)
        if self.manifest.joins == "tunnel":
            return  # no adapter: the gateway joins the tunnel
        cf = ctx.containerfile("adapter")
        if not cf.exists():
            raise ProviderError(f"{self.name}: no adapter Containerfile at {cf}")
        podman.build(
            ctx.adapter_image,
            str(cf),
            str(cf.parent),
            labels={"app": paths.APP, paths.MODULE_LABEL: self.name},
        )

    def status(self, ctx: ProviderContext) -> ProviderStatus:
        # A tunnel provider needs BOTH images: the tunnel (pulled or built) and the
        # locally-built adapter. Report ready only when both are present.
        status = super().status(ctx)
        if self.manifest.joins != "tunnel":
            status.image_present = status.image_present and podman.image_exists(ctx.adapter_image)
        return status


def _log_tail(container: str, lines: int = 8, marker: str | None = None) -> str:
    """The last lines a container logged, for an error about it; nothing when it
    logged nothing (or is already gone). With a module's `log_marker` (the prefix
    its own entrypoint logs with, "kf-myst:"), those lines are quoted instead of
    whatever a chatty daemon printed last — the ones that say what it was doing."""
    try:
        text = podman.logs(container, tail=400 if marker else lines)
    except Exception:  # noqa: BLE001 - the error being built matters more
        return ""
    found = [ln for ln in text.splitlines() if ln.strip()]
    if marker:
        own = [ln for ln in found if marker in ln]
        found = own or found
    tail = found[-lines:]
    return ("\n  its log ends:\n  " + "\n  ".join(tail)) if tail else ""


def _label(spec: ContainerSpec, module: str, lease: str | None, *, role: str) -> None:
    """What kiwi-proxy finds its containers by: set here, so a plugin need not."""
    spec.labels.setdefault(paths.ROLE_LABEL, role)
    spec.labels[paths.MODULE_LABEL] = module
    if lease:
        spec.labels[paths.LEASE_LABEL] = lease


def _safe_leases(provider: Provider, ctx: ProviderContext) -> list[Lease]:
    try:
        return provider.leases(ctx)
    except Exception:  # noqa: BLE001 - status must never raise
        return []
