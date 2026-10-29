"""Data model. Everything an exit is, and nothing that belongs in a secret store.

These models were kiwi-fox's (``kiwi_fox.core.models``) before the proxy engine was
split out; their shape is unchanged so profiles, plugins and consumers keep loading.
``Exit`` and ``Expose`` are new: an exit is a named, persistent upstream that any
consumer — kiwi-fox, kiwi-pentesting, a host application, a kiwi-server machine — can
bring up as a sealed gateway.
"""

from __future__ import annotations

import datetime as dt
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Endpoint(Strict):
    """A SOCKS5 endpoint. Every provider module exposes exactly this shape."""

    host: str
    port: int
    username: str | None = None
    has_password: bool = False  # the password itself lives in the secret store
    module: str | None = None  # provider module name; None = plain SOCKS5
    lease: str | None = None  # module-specific lease (9proxy port, myst provider_id)
    # Exit country requested from the provider. Persisted separately from lease
    # because for some modules the two are distinct axes (a myst provider_id and a
    # country), so it is replayed on every bring-up to keep the exit — and anything
    # a consumer froze for it, like a browser fingerprint — coherent.
    country: str | None = None

    @property
    def label(self) -> str:
        who = f"{self.module}:" if self.module else ""
        return f"{who}{self.host}:{self.port}"


class ExitInfo(Strict):
    ip: str
    country: str | None = None
    city: str | None = None
    timezone: str | None = None
    asn: str | None = None
    seen: dt.datetime


class DnsConfig(Strict):
    # "resolver": dnscrypt-proxy in the gateway, upstream through the SOCKS5 exit.
    # "remote":   hand the hostname to the proxy (most native, no DNS adblock).
    mode: Literal["resolver", "remote"] = "resolver"
    upstream: str = "google"  # key into dns.UPSTREAMS
    blocklists: list[str] = Field(default_factory=lambda: ["oisd-big"])


class Expose(Strict):
    """Publish the gateway's SOCKS5 on the host, for applications that are not
    containers: a browser on the desktop, a tool, mesh clients of a server.

    The listener lives inside the sealed namespace, so everything it carries still
    leaves through the one permitted destination. It is a second listener beside
    the 127.0.0.1:1080 one joined containers use, and it can demand its own
    username/password (RFC 1929) — which it should whenever ``bind`` is not a
    loopback address.
    """

    bind: str = "127.0.0.1"  # host address the port is published on
    port: int  # host port
    username: str | None = None
    has_password: bool = False  # the password itself lives in the secret store

    @property
    def address(self) -> str:
        host = f"[{self.bind}]" if ":" in self.bind else self.bind
        return f"{host}:{self.port}"

    @property
    def loopback(self) -> bool:
        return self.bind in ("127.0.0.1", "::1", "localhost") or self.bind.startswith("127.")


class Exit(Strict):
    """One upstream, by name: where traffic leaves, how DNS resolves, and whether
    the SOCKS5 is also offered on the host. Bringing it up makes a gateway — a
    network namespace whose only route is this upstream — that containers join
    (``--network container:<gateway>``) and that ``expose`` publishes.

    ``owner`` names the application that created it ("kiwi-fox" for a browser
    identity's exit), or is None for one made with the kiwi-proxy CLI. It is a hint
    for listings and for not deleting another app's exit by accident, not access
    control.
    """

    id: str
    name: str
    created: dt.datetime
    endpoint: Endpoint
    dns: DnsConfig = Field(default_factory=DnsConfig)
    expose: Expose | None = None
    # What the forwarder does with a joined client's SOCKS credentials.
    #   inject       answer no-auth, send the exit's own pair upstream (Camoufox,
    #                Firefox, tools — everything but Tor Browser)
    #   passthrough  Tor Browser: accept its per-site username/password and send it
    #                upstream behind the exit's token, so Tor keeps a circuit per
    #                site (IsolateSOCKSAuth) while exits stay apart. A no-auth client
    #                in the same namespace still gets the exit's pair. Needs an
    #                isolation provider (tor) or credentials on the endpoint.
    socks_auth: Literal["inject", "passthrough"] = "inject"
    owner: str | None = None
    last_exit: ExitInfo | None = None
    notes: str = ""


class ProviderRecord(Strict):
    """One verified exit, cached across exits. Provider geo is self-reported; this is measured."""

    module: str
    lease: str  # provider_id / port / address
    ip: str
    subnet: str | None = None
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    quality: float | None = None
    verified_at: dt.datetime


# ---------------------------------------------------------------- provider plugins
# A provider module turns some upstream (Tor, a VPN tunnel, a residential-proxy
# account, a Mysterium node) into plain SOCKS5 and exposes nothing else — the
# gateway, forwarder, firewall rule and DNS design stay single-shaped (see
# docs/decisions.md). kiwi-proxy discovers modules under paths.modules_dir(); each
# ships a provider.py exposing PROVIDER (a Provider) and MANIFEST.

ProviderAuth = Literal["none", "isolation", "account"]
#   none       the exposed SOCKS5 takes no credentials
#   isolation  any user/pass is accepted and used only to separate circuits/sessions
#              per exit (Tor IsolateSOCKSAuth); kiwi-proxy mints a per-exit token
#   account    fixed credentials the user holds with the provider (9proxy login);
#              supplied as the exit endpoint's own username/password


class Lease(Strict):
    """One selectable exit a provider can bring up: a Tor exit country, a gluetun
    server, a 9proxy residential port, a Mysterium provider. ``id`` is what the
    user passes as ``--lease`` and what is stored on the Endpoint; the rest is for
    display only."""

    id: str
    label: str | None = None
    country: str | None = None
    city: str | None = None
    detail: str | None = None


class ProviderManifest(Strict):
    """Static metadata a provider module declares about itself."""

    name: str  # the module id: tor, vpn, 9proxy, mysterium. Also Endpoint.module.
    title: str
    description: str = ""
    version: str = "0.0.0"
    # True when the module runs its own container(s) that become the SOCKS5
    # upstream; False for a module that only tags an already-remote SOCKS5.
    runs_container: bool = True
    # The podman image the module's container runs, built from its Containerfile.
    # None lets kiwi-proxy derive the conventional name (kiwi-proxy/<name>:latest).
    image: str | None = None
    # SOCKS5 port the provider container listens on, inside the providers network.
    socks_port: int = 1080
    auth: ProviderAuth = "none"
    # Does using this provider require an account / subscription / identity?
    needs_account: bool = False
    # Host binaries `kiwi-proxy module doctor` checks for, beyond podman.
    requires: list[str] = Field(default_factory=list)
    # Free-form notes surfaced in `kiwi-proxy module list`.
    notes: str = ""


class ProviderStatus(Strict):
    """A provider's live state, for `kiwi-proxy module status` and doctor."""

    name: str
    installed: bool = True
    image_present: bool = False
    running: bool = False
    containers: list[str] = Field(default_factory=list)
    leases: list[str] = Field(default_factory=list)
    detail: str = ""


class ContainerSpec(Strict):
    """What a gateway, a provider or a consumer asks podman for. Golden-file
    tested; keep it declarative."""

    name: str
    image: str
    network: str  # "container:<gateway>", "pasta", or a bridge name
    ip: str | None = None  # static address on a bridge network (providers only)
    restart: str | None = None  # podman restart policy, e.g. "on-failure"
    env: dict[str, str] = Field(default_factory=dict)
    volumes: list[tuple[str, str, str]] = Field(default_factory=list)  # src, dst, opts
    args: list[str] = Field(default_factory=list)  # command line after the image
    devices: list[str] = Field(default_factory=list)
    tmpfs: list[str] = Field(default_factory=list)
    secrets: list[tuple[str, str]] = Field(default_factory=list)  # secret name, target path
    publish: list[str] = Field(default_factory=list)  # [host-ip:]host-port:container-port[/proto]
    cap_drop: list[str] = Field(default_factory=lambda: ["all"])
    cap_add: list[str] = Field(default_factory=list)
    security_opt: list[str] = Field(default_factory=lambda: ["no-new-privileges"])
    userns: str | None = "keep-id"
    labels: dict[str, str] = Field(default_factory=dict)
