"""Exit -> gateway: a network namespace whose only route is one upstream.

The gateway container owns the namespace. nftables in it default-drops everything
but the one permitted destination — the exit's SOCKS5, or the provider container
that produces it — so the kill switch is the absence of a route rather than
software that has to notice. Inside the namespace:

    127.0.0.1:1080   the forwarder: unauthenticated SOCKS5 for whoever joined,
                     adding the upstream's credentials on the way out
    127.0.0.2:53     dnscrypt-proxy (resolver mode): DoH through the same exit
    0.0.0.0:1081     only when the exit is exposed: the same forwarder, published
                     on the host (``--publish``), optionally password-protected

A consumer joins with ``--network container:<gateway>`` — kiwi-fox's browser, a
kiwi-pentesting tool — and has no routing table of its own. An application on the
host uses the exposed port instead. Either way every byte leaves through the exit.

This was the network half of kiwi-fox's ``core/launch.py``. kiwi-fox now calls
``up()`` with its profile's exit and joins the browser to ``Gateway.name``.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import dns, endpoint, exits, paths, podman, providers, secrets, selection
from .models import ContainerSpec, Exit, ExitInfo, ProviderRecord

FORWARDER_PORT = 1080
FORWARDER = f"127.0.0.1:{FORWARDER_PORT}"
RESOLVER = dns.LISTEN_ADDR
# The host listener's port inside the namespace. Fixed: the host side of the
# mapping is the exit's own `expose.port`.
EXPOSE_PORT = 1081
READY_MARK = "ready — the namespace is sealed"


class GatewayError(RuntimeError):
    pass


@dataclass
class Gateway:
    """A running gateway, and everything a consumer needs to use it."""

    exit_id: str
    name: str  # the container; join it with --network container:<name>
    forwarder: str = FORWARDER  # SOCKS5 inside the namespace, no auth
    resolver: str | None = None  # inside the namespace, in resolver mode
    resolv_conf: str | None = None  # host file to mount at /etc/resolv.conf in a joiner
    expose: str | None = None  # host address of the published SOCKS5, when exposed
    info: ExitInfo | None = None  # the measured exit, when it was measured
    reused: bool = False  # it was already up with these settings
    notes: list[str] = field(default_factory=list)

    @property
    def network(self) -> str:
        return f"container:{self.name}"

    def as_dict(self) -> dict:
        d = asdict(self)
        d["network"] = self.network
        d["info"] = self.info.model_dump(mode="json") if self.info else None
        return d


@dataclass
class EndpointPlan:
    """How to wire the gateway to this exit's upstream."""

    ip: str  # literal address the gateway's firewall permits
    port: int  # SOCKS5 port on that address
    network: str  # "pasta" for a remote exit, the providers bridge for a local one
    info: ExitInfo | None = None  # measured exit, when the host could reach it
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------- prep
def _provider_auth(module: str | None) -> str:
    """The managed provider's auth mode, or 'none' for a plain/remote endpoint."""
    if not providers.manages(module):
        return "none"
    try:
        return providers.manifest_of(module).auth
    except providers.ProviderError:
        return "none"


def credentials(ex: Exit, password: str | None = None) -> tuple[str, str]:
    """What the forwarder sends upstream: the endpoint's own credentials, or — for
    an isolation provider such as Tor — a stable per-exit token, so the provider
    gives each exit its own circuit (IsolateSOCKSAuth): same exit -> same circuit
    across bring-ups, different exits -> different circuits. The token is an
    isolation key, not a secret, so deriving it from the exit id is fine; kiwi-fox's
    exits use the profile id, so the token is the one kiwi-fox always minted."""
    user = ex.endpoint.username or ""
    if password is None:
        password = secrets.lookup(ex.id, kind="endpoint")
    password = password or ""
    if not user and _provider_auth(ex.endpoint.module) == "isolation":
        user, password = f"kf-{ex.id[:16]}", ex.id
    return user, password


def write_credentials(ex: Exit, password: str | None = None) -> str:
    """Credentials reach the gateway as a podman secret, never as container env
    (`podman inspect` shows env) and never as a bind-mounted 0600 file (the
    gateway runs as container-root, a subuid, so it could not read it)."""
    name = paths.creds_secret_name(ex.id)
    user, password = credentials(ex, password)
    podman.secret_set(name, f"{user}\n{password}\n")
    return name


def write_expose_credentials(ex: Exit, password: str | None = None) -> str | None:
    """What the host listener demands, as its own podman secret. None: no auth."""
    if not ex.expose or not ex.expose.username:
        return None
    if password is None:
        password = secrets.lookup(ex.id, kind="expose")
    if not password:
        raise GatewayError(
            f"exit {ex.name!r} exposes its SOCKS5 to user {ex.expose.username!r} "
            "but no password is stored for it"
        )
    name = paths.expose_secret_name(ex.id)
    podman.secret_set(name, f"{ex.expose.username}\n{password}\n")
    return name


def blocklist_in_gateway(ex: Exit) -> str:
    """This exit's merged list, as the gateway sees it (the directory is mounted,
    not the file, so a daily update's atomic replace reaches running gateways)."""
    dns.merged_blocklist(ex.dns.blocklists)  # make sure the file exists before it is mounted
    return f"/blocklist/{dns.merged_name(ex.dns.blocklists)}"


def write_resolver_config(ex: Exit) -> Path | None:
    if ex.dns.mode != "resolver":
        return None
    dns.merged_blocklist(ex.dns.blocklists)
    cfg = dns.toml_config(
        ex.dns.upstream,
        blocklist=blocklist_in_gateway(ex),
        forwarder="127.0.0.1",
        forwarder_port=FORWARDER_PORT,
    )
    path = paths.exit_runtime_dir(ex.id) / "dnscrypt-proxy.toml"
    path.write_text(cfg)
    return path


def write_resolv_conf(ex: Exit) -> Path | None:
    """A joined container has its own mount namespace, so it needs its own
    resolv.conf pointing at the gateway's resolver. Mounted rather than written,
    because --dns cannot be combined with --network container:."""
    if ex.dns.mode != "resolver":
        return None
    path = paths.exit_runtime_dir(ex.id) / "resolv.conf"
    path.write_text(f"nameserver {dns.LISTEN_ADDR}\noptions edns0 trust-ad\n")
    return path


# -------------------------------------------------------------------- specs
def gateway_spec(
    ex: Exit,
    endpoint_ip: str,
    *,
    endpoint_port: int | None = None,
    network: str = "pasta",
    labels: dict[str, str] | None = None,
) -> ContainerSpec:
    """The gateway container for an exit. `labels` are the consumer's own, added
    on top of kiwi-proxy's (kiwi-fox sets app=kiwi-fox and kiwi-fox.profile)."""
    rt = paths.exit_runtime_dir(ex.id)
    secret = paths.creds_secret_name(ex.id)
    target = f"/run/secrets/{secret}"
    volumes: list[tuple[str, str, str]] = []
    # A tunnel exit (a VPN): the gateway joins the tunnel's namespace and its
    # forwarder connects targets itself; the tunnel's firewall is the kill switch.
    tunnel = network.startswith("container:")
    upstream = (
        {"KF_UPSTREAM": "direct"}
        if tunnel
        else {
            "KF_ENDPOINT_IP": endpoint_ip,
            "KF_ENDPOINT_PORT": str(endpoint_port or ex.endpoint.port),
        }
    )
    env = {
        **upstream,
        "KF_FORWARDER_PORT": str(FORWARDER_PORT),
        "KF_DNS_MODE": ex.dns.mode,
        "KF_CREDS_FILE": target,
        # In resolver mode the forwarder resolves a CONNECT-by-name itself, via
        # this resolver, and connects the upstream by IPv4: one address family
        # for everything behind the exit (a SOCKS upstream given a name may pick
        # AAAA). Remote-DNS exits (Tor) pass names through.
        **({"KF_RESOLVER": RESOLVER} if ex.dns.mode == "resolver" else {}),
    }
    # Only set when it differs, so an inject gateway's env is what it always was.
    if ex.socks_auth != "inject":
        env["KF_SOCKS_AUTH"] = ex.socks_auth
    secrets_: list[tuple[str, str]] = [(secret, target)]
    if network == paths.PROVIDERS_NETWORK and selection.wants_control(ex):
        # Tor Browser's control port: the exit's own Tor, behind the forwarder's filter
        ctl = paths.control_secret_name(ex.id)
        env["KF_CONTROL_IP"] = endpoint_ip
        env["KF_CONTROL_PORT"] = str(selection.CONTROL_PORT)
        env["KF_CONTROL_PASSWORD_FILE"] = f"/run/secrets/{ctl}"
        secrets_.append((ctl, f"/run/secrets/{ctl}"))
    publish: list[str] = []
    if ex.dns.mode == "resolver":
        # ",z" relabels for SELinux: without it an enforcing host denies the
        # container read access to anything under $HOME.
        volumes.append((str(rt / "dnscrypt-proxy.toml"), "/run/kf/dnscrypt-proxy.toml", "ro,z"))
    if ex.dns.blocklists:
        # The list reaches the forwarder in both DNS modes: a client that hands it
        # names — socks5h on the host port, and every browser in remote mode,
        # Tor Browser included — is refused there, resolver or not. In resolver
        # mode the resolver refuses the same names first.
        volumes.append((str(paths.blocklists_dir()), "/blocklist", "ro,z"))
        env["KF_BLOCKLIST"] = blocklist_in_gateway(ex)
    all_labels = {
        paths.ROLE_LABEL: "gateway",
        paths.EXIT_LABEL: ex.id,
    }
    if ex.endpoint.module and providers.manages(ex.endpoint.module):
        all_labels[paths.MODULE_LABEL] = ex.endpoint.module
        if lease := selection.lease_for(ex):
            all_labels[paths.LEASE_LABEL] = lease
    if ex.expose:
        env["KF_EXPOSE_PORT"] = str(EXPOSE_PORT)
        # A VPN exit's namespace is its tunnel's: podman publishes the port there
        # (the module does, see expose_publish), never on a container that joined.
        if not tunnel:
            publish.append(expose_publish(ex))
        all_labels[paths.EXPOSE_LABEL] = ex.expose.address
        if ex.expose.username:
            esecret = paths.expose_secret_name(ex.id)
            etarget = f"/run/secrets/{esecret}"
            secrets_.append((esecret, etarget))
            env["KF_EXPOSE_CREDS_FILE"] = etarget
    all_labels.update(labels or {})
    return ContainerSpec(
        name=paths.gateway_name(ex.id),
        image=paths.GATEWAY_IMAGE,
        # A plain/remote endpoint keeps pasta — it is a public address the gateway
        # reaches directly. A managed local provider lives on the shared providers
        # bridge, so the gateway joins that bridge to reach exactly its SOCKS5.
        network=network,
        env=env,
        volumes=volumes,
        secrets=secrets_,
        publish=publish,
        cap_drop=["all"],
        # NET_ADMIN to build the ruleset, NET_BIND_SERVICE because the resolver
        # listens on 53 and dropping all caps denies that even to container-root.
        # NET_RAW is deliberately NOT granted: nftables, dnscrypt-proxy and the
        # forwarder use no raw sockets, and on the shared providers bridge it would
        # let a compromised gateway or joiner ARP-spoof sibling containers.
        cap_add=["NET_ADMIN", "NET_BIND_SERVICE"],
        security_opt=["no-new-privileges"],
        userns=None,  # needs container-root to configure its own netns
        labels=all_labels,
    )


def expose_publish(ex: Exit) -> str:
    """The podman --publish for an exit's host SOCKS5 port (the gateway's, or on a
    VPN exit its tunnel's, whose namespace the gateway shares)."""
    bind = f"[{ex.expose.bind}]" if ":" in ex.expose.bind else ex.expose.bind
    return f"{bind}:{ex.expose.port}:{EXPOSE_PORT}/tcp"


def config_hash(spec: ContainerSpec, resolver_cfg: Path | None) -> str:
    """What a gateway was started with, so a second consumer asking for the same
    exit can tell whether the running one is it. Labels are left out: they say who
    asked (kiwi-fox labels its gateways, `kiwi-proxy up` does not), not how the
    namespace is built."""
    digest = hashlib.sha256()
    probe = spec.model_copy(deep=True)
    probe.labels = {}
    digest.update("\0".join(podman.spec_args(probe)).encode())
    if resolver_cfg and resolver_cfg.exists():
        digest.update(resolver_cfg.read_bytes())
    return digest.hexdigest()[:16]


# ------------------------------------------------------------------- planning
def tunnel_of(ex: Exit) -> str | None:
    """The provider container a tunnel exit's gateway joins (a VPN: gluetun, one
    per exit), or None for an exit whose gateway connects to a SOCKS5."""
    module = ex.endpoint.module
    if not providers.manages(module):
        return None
    try:
        _prov, manifest = providers.load(module)
    except providers.ProviderError:
        return None
    if manifest.joins != "tunnel":
        return None
    return providers.container_of(module, selection.lease_for(ex))


def is_tunnel(ex: Exit) -> bool:
    """Does this exit's namespace route through a tunnel (TCP and UDP), so a member
    needs no SOCKS5 to reach anything? Kiwi Custodia leaves its tun2socks out then."""
    return tunnel_of(ex) is not None


def _provider_up(prov, ctx, ex: Exit):
    """Bring an exit's provider up: with its selection (only, never) for a module
    that takes one, in a container of its own for that selection."""
    sel = selection.for_exit(ex)
    if sel is None:
        return prov.up(ctx, lease=ex.endpoint.lease, country=ex.endpoint.country)
    if problems := sel.problems():
        raise providers.ProviderError(f"{ex.name}: " + "; ".join(problems))
    return prov.up(ctx, lease=selection.lease_for(ex), country=ex.endpoint.country, selection=sel)


def ensure_provider(ex: Exit) -> EndpointPlan:
    """Bring up a managed provider (idempotent) and return its live SOCKS5 address
    on the providers bridge. The provider's own exit is measured later, through the
    gateway, because the host is not on that rootless bridge."""
    module = ex.endpoint.module
    prov, manifest = providers.load(module)
    ctx = providers.context_for(module, manifest)
    try:
        # Replay both the lease and the country stored on the exit, so an exit
        # selected by country at creation is reproduced after a provider teardown
        # (not silently reset to the provider's default, which would contradict
        # whatever a consumer froze for it).
        live = _provider_up(prov, ctx, ex)
    except providers.ProviderError as exc:
        raise GatewayError(f"provider {module!r} could not start: {exc}") from exc
    lease = f" (lease {ex.endpoint.lease})" if ex.endpoint.lease else ""
    if chosen := selection.summary(ex.endpoint):
        lease += f" ({chosen})"
    if manifest.joins == "tunnel":
        name = providers.container_of(module, selection.lease_for(ex))
        return EndpointPlan(
            ip="",
            port=0,
            network=f"container:{name}",
            info=None,
            notes=[f"provider {module}: tunnel up in {name}{lease}"],
        )
    return EndpointPlan(
        ip=live.host,
        port=live.port,
        network=paths.PROVIDERS_NETWORK,
        info=None,
        notes=[f"provider {module} up at {live.host}:{live.port}{lease}"],
    )


def plan(ex: Exit, password: str | None = None, *, measure: bool = True) -> EndpointPlan:
    """Decide the gateway's upstream and, for a remote exit, measure it.

    A managed local provider is brought up on the providers bridge; a plain exit is
    resolved to a literal address on the host and probed so a region is known
    before anything uses it."""
    if providers.manages(ex.endpoint.module):
        return ensure_provider(ex)

    try:
        endpoint.reachable(ex.endpoint)
    except endpoint.EndpointError as exc:
        raise GatewayError(f"{ex.name}: {exc}") from exc
    notes: list[str] = []
    endpoint_ip = endpoint.resolve(ex.endpoint.host)
    if endpoint_ip != ex.endpoint.host:
        notes.append(f"resolved {ex.endpoint.host} -> {endpoint_ip}")
    if not measure:
        return EndpointPlan(endpoint_ip, ex.endpoint.port, "pasta", None, notes)
    if password is None:
        password = secrets.lookup(ex.id, kind="endpoint")
    try:
        info = endpoint.preflight(ex.endpoint, password)
    except Exception as exc:  # noqa: BLE001 - never block a bring-up on this
        notes.append(f"pre-flight could not reach the exit: {exc}")
        return EndpointPlan(endpoint_ip, ex.endpoint.port, "pasta", None, notes)
    if ex.endpoint.module:
        exits.record_provider(
            ProviderRecord(
                module=ex.endpoint.module,
                lease=ex.endpoint.lease or ex.endpoint.label,
                ip=info.ip,
                country=info.country,
                city=info.city,
                asn=info.asn,
                verified_at=dt.datetime.now(dt.UTC),
            )
        )
    return EndpointPlan(endpoint_ip, ex.endpoint.port, "pasta", info, notes)


# ------------------------------------------------------------------- lifecycle
def _held_path(exit_id: str) -> Path:
    return paths.holds_dir() / exit_id


def hold(exit_id: str) -> None:
    """Keep this exit up until someone downs it on purpose: a consumer finishing
    with it (`release`) leaves it alone."""
    paths.holds_dir().mkdir(parents=True, exist_ok=True)
    _held_path(exit_id).touch()


def unhold(exit_id: str) -> None:
    _held_path(exit_id).unlink(missing_ok=True)


def held(exit_id: str) -> bool:
    return _held_path(exit_id).exists()


def is_up(exit_id: str) -> bool:
    return podman.is_running(paths.gateway_name(exit_id))


def wait_ready(name: str, timeout: float = 30.0) -> bool:
    """Until the gateway says its namespace is sealed and its services listen."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not podman.is_running(name):
            return False
        if READY_MARK in podman.logs(name, tail=200):
            return True
        time.sleep(0.2)
    return False


def _running_dependents(name: str, ignore: tuple[str, ...] = ()) -> list[str]:
    return [d for d in podman.dependents(name) if d not in ignore and podman.is_running(d)]


def kept_as(member: str) -> str | None:
    """The image a member asked to be committed to before it is removed, or None."""
    return podman.labels(member).get(paths.SNAPSHOT_LABEL) or None


def _remove_member(name: str) -> None:
    """Remove a container that joined a gateway. One that asked to be kept
    (`kiwi-proxy.snapshot=<image>` — a Kiwi Custodia box) is committed to that
    image first and stays put when that fails: a lost route is recoverable, what
    someone installed in it is not."""
    image = kept_as(name)
    if image:
        try:
            podman.commit(name, image)
        except podman.PodmanError as exc:
            raise GatewayError(
                f"{name} asked to be kept as {image} before it is removed, and that "
                f"failed ({exc}); it was left in place"
            ) from exc
    podman.rm(name)


def _ensure_current_gateway_image() -> None:
    """Rebuild the gateway image when kiwi-proxy was updated since it was built
    (its forwarder, its firewall): a gateway from an older image would lack what
    this version starts it with. A rebuild that fails stops the start."""
    from . import setup

    if setup.image_state(paths.GATEWAY_IMAGE, "gateway") == "current":
        return
    try:
        setup.build_images()
    except Exception as exc:  # noqa: BLE001 - a build, a network
        raise GatewayError(
            f"the gateway image is older than kiwi-proxy and could not be rebuilt ({exc}); "
            "`kiwi-proxy setup`"
        ) from exc
    if setup.image_state(paths.GATEWAY_IMAGE, "gateway") != "current":
        raise GatewayError("the gateway image could not be rebuilt; `kiwi-proxy setup`")


def up(
    ex: Exit,
    *,
    password: str | None = None,
    expose_password: str | None = None,
    labels: dict[str, str] | None = None,
    replace: bool = False,
    keep: bool = False,
    measure: bool = True,
) -> Gateway:
    """Bring the exit's gateway up, or hand back the one already running.

    Idempotent: a gateway running with the same settings is reused, so a browser
    and a pentest tool on one identity share one namespace and one exit. One
    running with *different* settings is replaced only when nothing is using it, or
    when `replace` says to — replacing removes whoever joined it, because podman
    cannot swap a namespace out from under its members. `replace` also restarts a
    gateway whose settings match, which is how a changed password takes effect.

    `password` / `expose_password` let a consumer that keeps its own secrets (kiwi-fox,
    in its keyring) hand them over; otherwise kiwi-proxy's secret store is asked.
    `keep` marks the exit held (see `hold`).
    """
    if not podman.available():
        raise GatewayError("podman not found")
    notes: list[str] = []
    if tunnel := tunnel_of(ex):
        if ex.dns.mode != "resolver":
            raise GatewayError(
                f"exit {ex.name!r}: a VPN exit resolves names itself (DNS: resolver)"
            )
        wanted = ex.expose.address if ex.expose else ""
        if (
            podman.is_running(tunnel)
            and podman.labels(tunnel).get(paths.EXPOSE_LABEL, "") != wanted
        ):
            # The host port is published on the tunnel, which only a new tunnel
            # changes: start the exit over.
            down(ex.id)
            notes.append("the VPN tunnel was started again for the host SOCKS5 port")
        elif podman.exists(paths.gateway_name(ex.id)) and not podman.is_running(tunnel):
            # Its namespace was the tunnel's, which is gone: the gateway and its
            # members have no route. A new tunnel is a new namespace; start over.
            down(ex.id)
            notes.append("the VPN tunnel had ended; its gateway was taken down first")
    pl = plan(ex, password, measure=measure)
    notes += pl.notes
    resolver_cfg = write_resolver_config(ex)
    resolv = write_resolv_conf(ex)
    spec = gateway_spec(ex, pl.ip, endpoint_port=pl.port, network=pl.network, labels=labels)
    spec.labels[paths.CONFIG_LABEL] = config_hash(spec, resolver_cfg)

    def result(reused: bool, info: ExitInfo | None) -> Gateway:
        if keep:
            hold(ex.id)
        return Gateway(
            exit_id=ex.id,
            name=spec.name,
            resolver=RESOLVER if ex.dns.mode == "resolver" else None,
            resolv_conf=str(resolv) if resolv else None,
            expose=ex.expose.address if ex.expose else None,
            info=info,
            reused=reused,
            notes=notes,
        )

    if podman.is_running(spec.name):
        current = podman.labels(spec.name).get(paths.CONFIG_LABEL)
        if current == spec.labels[paths.CONFIG_LABEL] and not replace:
            return result(True, pl.info)
        users = _running_dependents(spec.name)
        if (users or held(ex.id)) and not replace:
            who = ", ".join(users) if users else "kept up with `kiwi-proxy up`"
            raise GatewayError(
                f"exit {ex.name!r} is up with other settings and in use ({who}); "
                "down it first, or replace it"
            )
        notes.append("replaced a gateway that was running with other settings")

    if ex.socks_auth == "passthrough" and not credentials(ex, password)[0]:
        # The forwarder refuses to start without a token to put in front of the
        # client's credentials; say why here instead of in its log.
        raise GatewayError(
            f"exit {ex.name!r}: passthrough needs an isolation provider (tor) or a "
            "username on the endpoint"
        )
    write_credentials(ex, password)
    write_expose_credentials(ex, expose_password)
    if pl.network == paths.PROVIDERS_NETWORK and selection.wants_control(ex):
        podman.secret_set(paths.control_secret_name(ex.id), selection.for_exit(ex).control_password)
    _ensure_current_gateway_image()
    # Whoever joined the old namespace makes the gateway a dependent container:
    # podman refuses to replace it while they exist ("has dependent containers
    # which must be removed before it"). They have no route without it anyway.
    for dep in podman.dependents(spec.name):
        _remove_member(dep)
    podman.start(spec)
    if not podman.is_running(spec.name):
        raise GatewayError(f"gateway failed to start:\n{podman.logs(spec.name)}")
    if not wait_ready(spec.name):
        logs = podman.logs(spec.name)
        if not podman.is_running(spec.name):
            raise GatewayError(f"gateway exited during start:\n{logs}")
        notes.append("gateway did not report ready in time; continuing")
    info = pl.info
    if info is None and measure:
        try:
            info = measure_exit(spec.name)
        except GatewayError as exc:
            notes.append(f"could not measure the exit through the gateway: {exc}")
    if info and exits.exists(ex.id):
        exits.record_exit(ex, info)
    return result(False, info)


def _release_provider(module: str | None, lease: str | None, *, exclude: str) -> None:
    """Stop a managed provider once no running gateway still uses it. A provider
    container is shared across every exit — from every consumer — on the same
    module+lease, so it must not be torn down while another is still using it."""
    if not providers.manages(module):
        return
    for c in podman.ps(all_=False, labels={paths.ROLE_LABEL: "gateway"}):
        lab = c.get("Labels") or {}
        name = (c.get("Names") or [""])[0]
        if (
            name != exclude
            and lab.get(paths.MODULE_LABEL) == module
            and lab.get(paths.LEASE_LABEL) == (lease or None)
        ):
            return
    with contextlib.suppress(providers.ProviderError):
        prov, manifest = providers.load(module)
        ctx = providers.context_for(module, manifest)
        prov.down(ctx, lease=lease)


def down(exit_id: str) -> None:
    """Tear the gateway down, whoever is using it: joined containers go first (they
    have no route without it), then the gateway, its secrets, and the provider if
    no other gateway still exits through it."""
    unhold(exit_id)
    if not podman.available():
        return
    name = paths.gateway_name(exit_id)
    lab = podman.labels(name)
    for dep in podman.dependents(name):
        _remove_member(dep)
    podman.rm(name)
    podman.secret_rm(paths.creds_secret_name(exit_id))
    podman.secret_rm(paths.control_secret_name(exit_id))
    podman.secret_rm(paths.expose_secret_name(exit_id))
    module, lease = lab.get(paths.MODULE_LABEL), lab.get(paths.LEASE_LABEL)
    if not module and exits.exists(exit_id):
        # No gateway to read the labels from — it never came up, the provider
        # may have — so the exit says which provider to let go of.
        ex = exits.load(exit_id)
        if providers.manages(ex.endpoint.module):
            module, lease = ex.endpoint.module, selection.lease_for(ex)
    if module:
        _release_provider(module, lease, exclude=name)


def release(exit_id: str, *, ignore: tuple[str, ...] = ()) -> bool:
    """A consumer is done with this exit. Tear the gateway down unless someone else
    still uses it — another running container joined to it (other than `ignore`),
    or a hold. Returns True when it was torn down.

    This is what kiwi-fox calls when a browser window closes: a pentest tool on the
    same identity, or a `kiwi-proxy up` of it, keeps the exit alive."""
    name = paths.gateway_name(exit_id)
    if held(exit_id) or _running_dependents(name, ignore):
        return False
    down(exit_id)
    return True


# ------------------------------------------------------------------- measuring
def probe(ex) -> ExitInfo:
    """What the world sees through an exit, measured now: through its gateway if
    up, else through one brought up for the probe and taken down again. Recorded
    on the exit either way. This is what "Check the exit" does for an exit that is
    not running, so an exit need not be up to learn where it leaves."""
    name = paths.gateway_name(ex.id)
    if podman.is_running(name):
        info = measure_exit(name)
        exits.record_exit(ex, info)
        return info
    gw = up(ex, measure=True)
    try:
        if gw.info is None:
            info = measure_exit(gw.name)
            exits.record_exit(ex, info)
            return info
        return gw.info
    finally:
        down(ex.id)


def renews(ex) -> bool:
    """Can this exit get a new IP on request (a 9proxy exit)?"""
    module = ex.endpoint.module
    if not providers.manages(module):
        return False
    try:
        return callable(getattr(providers.get_provider(module), "renew", None))
    except providers.ProviderError:
        return False


def renew(ex) -> tuple[list[str], ExitInfo | None]:
    """A new IP for the exit, from its module (9proxy: one from the balance), then
    measured through the gateway when it is up. Returns the module's lines."""
    if not renews(ex):
        raise GatewayError(f"exit {ex.name!r}: its module gives no new IPs on request")
    module = ex.endpoint.module
    prov, manifest = providers.load(module)
    ctx = providers.context_for(module, manifest)
    try:
        lines = list(prov.renew(ctx, lease=_provider_lease(ex), country=ex.endpoint.country))
    except providers.ProviderError as exc:
        raise GatewayError(str(exc)) from exc
    info = None
    name = paths.gateway_name(ex.id)
    if podman.is_running(name):
        with contextlib.suppress(GatewayError):
            info = measure_exit(name)
            exits.record_exit(ex, info)
    return lines, info


def _provider_lease(ex) -> str | None:
    """The lease of the provider container behind an exit: what its running
    gateway was started with (a changed selection or Eyes preference only applies
    at the next start), else what the exit asks for now."""
    name = paths.gateway_name(ex.id)
    if podman.exists(name):
        lab = podman.labels(name)
        if lab.get(paths.MODULE_LABEL) == ex.endpoint.module:
            return lab.get(paths.LEASE_LABEL) or None
    return selection.lease_for(ex)


def provider_alive(ex) -> bool | None:
    """For a module exit whose gateway is up: is its provider container running?
    None for a plain endpoint (nothing to ask). A Mysterium node that gave up
    leaves a gateway that refuses everything — this is how a row can say so."""
    module = ex.endpoint.module
    if not providers.manages(module):
        return None
    return providers.lease_alive(module, _provider_lease(ex))


def exit_logs(ex, lines: int = 200) -> list[tuple[str, str]]:
    """(container, recent log) for the containers behind an exit, so someone can
    see whether the provider connected and what any error is: the module's own
    container (Mysterium/VPN node, the tor/9proxy provider), its tunnel adapter
    where there is one, and the gateway — whichever exist right now."""
    out: list[tuple[str, str]] = []
    if not podman.available():
        return out
    module = ex.endpoint.module
    if providers.manages(module):
        try:
            prov, manifest = providers.load(module)
            ctx = providers.context_for(module, manifest)
            for name in (
                providers.container_of(module, _provider_lease(ex)),
                ctx.adapter_name(_provider_lease(ex)),
            ):
                if podman.exists(name):
                    out.append((name, podman.logs(name, tail=lines)))
        except providers.ProviderError:
            pass
    gw = paths.gateway_name(ex.id)
    if podman.exists(gw):
        out.append((gw, podman.logs(gw, tail=lines)))
    return out


def measure_exit(gateway: str, url: str | None = None) -> ExitInfo:
    """What the world sees, asked from inside the namespace through the forwarder —
    so it works for every exit, including provider exits the host cannot reach.
    The ip-echo services in endpoint.GEO_URLS are asked in turn (or the one
    given): one may refuse an exit the next one serves."""
    failures: list[str] = []
    for geo in [url] if url else list(endpoint.GEO_URLS):
        proc = podman.exec_(gateway, ["kf-exitinfo", geo], timeout=45)
        if proc.returncode != 0:
            failures.append((proc.stderr or proc.stdout).strip() or f"{geo}: exit probe failed")
            continue
        try:
            return endpoint.parse_geo(proc.stdout)
        except endpoint.EndpointError as exc:
            failures.append(f"{geo}: {exc}")
    raise GatewayError("; ".join(failures) or "exit probe failed")


# --------------------------------------------------------------- housekeeping
def running() -> list[dict]:
    """Every gateway kiwi-proxy knows of, with its labels: what `ps` and consumers
    (kiwi-pentesting) list."""
    out = []
    for c in podman.ps(labels={paths.ROLE_LABEL: "gateway"}):
        lab = c.get("Labels") or {}
        out.append(
            {
                "name": (c.get("Names") or [""])[0],
                "exit_id": lab.get(paths.EXIT_LABEL),
                "state": c.get("State"),
                "app": lab.get("app"),
                "module": lab.get(paths.MODULE_LABEL),
                "lease": lab.get(paths.LEASE_LABEL),
                "expose": lab.get(paths.EXPOSE_LABEL),
            }
        )
    return out


def heal() -> list[str]:
    """Restart the provider behind a running gateway when it has died — a tunnel
    node whose session ended fails closed and exits — so the exit comes back on
    its own; the gateway, its members and its pinned address stay. If the new
    provider comes up on another address the gateway is torn down instead
    (reconcile's rule). Returns the gateways healed; a provider that will not
    come back is reported in the list as "name: why" and the gateway left as is
    (closed), for the next round."""
    healed: list[str] = []
    for gw in running():
        if gw["state"] != "running" or not gw["module"] or not gw["exit_id"]:
            continue
        module = gw["module"]
        if not providers.manages(module):
            continue
        if providers.lease_alive(module, gw["lease"]):
            continue
        try:
            ex = exits.load(gw["exit_id"])
        except exits.ExitError:
            continue
        if podman.container_env(gw["name"], "KF_UPSTREAM") == "direct":
            # A VPN exit: the gateway lived in the tunnel's namespace, which went
            # with it. Fail closed; the next start brings a new tunnel.
            down(gw["exit_id"])
            healed.append(f"{gw['name']}: the VPN tunnel ended; taken down")
            continue
        pinned = podman.container_env(gw["name"], "KF_ENDPOINT_IP")
        try:
            prov, manifest = providers.load(module)
            ctx = providers.context_for(module, manifest)
            prov.down(ctx, lease=selection.lease_for(ex))
            ep = _provider_up(prov, ctx, ex)
        except providers.ProviderError as exc:
            healed.append(f"{gw['name']}: {exc}")
            continue
        if pinned and ep.host != pinned:
            down(gw["exit_id"])  # not the address the firewall permits: fail closed
            healed.append(f"{gw['name']}: provider came back on {ep.host}, not {pinned}; torn down")
            continue
        healed.append(gw["name"])
    return healed


def reconcile() -> list[str]:
    """Fail closed any running gateway whose permitted provider address has drifted.

    Providers get a deterministic static IP, so this should never fire; it is a
    backstop. If a gateway's pinned KF_ENDPOINT_IP no longer matches its provider's
    current bridge address, the gateway's firewall would be pointing at whatever now
    holds that address — a wrong exit, and in account-auth mode a credential leak —
    so the gateway is torn down (its members lose their route) rather than left live.
    """
    stopped = []
    for gw in running():
        if gw["state"] != "running" or not gw["module"] or not gw["exit_id"]:
            continue
        if not providers.manages(gw["module"]):
            continue
        pinned = podman.container_env(gw["name"], "KF_ENDPOINT_IP")
        current = podman.container_ip(
            providers.container_of(gw["module"], gw["lease"]), paths.PROVIDERS_NETWORK
        )
        if pinned and current and pinned != current:
            down(gw["exit_id"])
            stopped.append(gw["name"])
    return stopped


def reap() -> list[str]:
    """Tear down gateways nobody uses: exited ones, and running ones with no running
    member that are neither held nor exposed on the host. Then reconcile. Safe to
    call at any time."""
    cleaned = []
    for gw in running():
        if not gw["exit_id"]:
            continue
        if gw["state"] != "running" or not (
            held(gw["exit_id"]) or gw["expose"] or _running_dependents(gw["name"])
        ):
            down(gw["exit_id"])
            cleaned.append(gw["name"])
    return cleaned + reconcile()
