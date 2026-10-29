"""kiwi-proxy command line. Consumers use the Python API or `--json`; the CLI is the truth."""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import sys

from . import __version__, dns, endpoint, exits, gateway, paths, podman, providers, secrets
from .models import DnsConfig, Endpoint, Exit, Expose


def _p(*args: object) -> None:
    print(*args)


def _fail(msg: str) -> int:
    print(f"kiwi-proxy: {msg}", file=sys.stderr)
    return 1


def _json(payload: object) -> int:
    print(json.dumps(payload, indent=2, default=str))
    return 0


# ------------------------------------------------------------------ helpers
def _endpoint_from_module(module: str, *, lease: str | None, country: str | None):
    """A module-backed endpoint. Nothing is started: the gateway brings the provider
    up when the exit comes up, on the providers bridge."""
    if not providers.is_installed(module):
        raise providers.ProviderError(f"provider module {module!r} is not installed")
    _prov, manifest = providers.load(module)
    if not manifest.runs_container:
        raise providers.ProviderError(
            f"{module!r} does not produce its own endpoint; pass an ENDPOINT"
        )
    return Endpoint(
        host=paths.provider_static_ip(module, lease),
        port=manifest.socks_port,
        module=module,
        lease=lease,
        country=country,
    )


def parse_expose(spec: str) -> tuple[str, int]:
    """PORT, ADDR:PORT or [V6]:PORT."""
    spec = spec.strip()
    if spec.startswith("["):
        host, _, port = spec[1:].partition("]:")
    elif ":" in spec:
        host, _, port = spec.rpartition(":")
    else:
        host, port = "127.0.0.1", spec
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"cannot read {spec!r} as [ADDR:]PORT")
    return host or "127.0.0.1", int(port)


def _expose_from_args(a: argparse.Namespace) -> tuple[Expose | None, str | None]:
    if not a.expose:
        return None, None
    bind, port = parse_expose(a.expose)
    password = None
    if a.expose_user:
        if a.expose_password_stdin:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass(f"password for {a.expose_user} on {bind}:{port}: ")
        if not password:
            raise ValueError("an exposed SOCKS5 with a user needs a password")
    ex = Expose(bind=bind, port=port, username=a.expose_user, has_password=bool(password))
    if not ex.loopback and not ex.username and not a.expose_open:
        raise ValueError(
            f"{ex.address} is reachable from other machines; give it --expose-user, "
            "or say --expose-open to publish it without a password"
        )
    return ex, password


def _exit_line(ex: Exit) -> str:
    state = "up" if gateway.is_up(ex.id) else "down"
    expose = f" · host {ex.expose.address}" if ex.expose else ""
    owner = f" · {ex.owner}" if ex.owner else ""
    where = ex.endpoint.label
    if ex.endpoint.lease:
        where += f" ({ex.endpoint.lease})"
    elif ex.endpoint.country:
        where += f" ({ex.endpoint.country})"
    return f"{ex.name:16} {state:4} {where}{expose}{owner}"


def _exit_dict(ex: Exit) -> dict:
    d = json.loads(ex.model_dump_json())
    d["gateway"] = paths.gateway_name(ex.id)
    d["running"] = gateway.is_up(ex.id)
    d["held"] = gateway.held(ex.id)
    return d


def _dns_from_args(a: argparse.Namespace, base: DnsConfig | None = None) -> DnsConfig:
    cfg = (base or DnsConfig()).model_copy()
    if getattr(a, "dns", None):
        cfg.mode = a.dns
    if getattr(a, "upstream", None):
        if a.upstream not in dns.UPSTREAMS:
            raise ValueError(f"unknown upstream {a.upstream!r}; one of {', '.join(dns.UPSTREAMS)}")
        cfg.upstream = a.upstream
    if getattr(a, "blocklist", None):
        unknown = [b for b in a.blocklist if b not in dns.BLOCKLISTS]
        if unknown:
            raise ValueError(f"unknown blocklist {unknown}; one of {', '.join(dns.BLOCKLISTS)}")
        cfg.blocklists = a.blocklist
    return cfg


# ------------------------------------------------------------------ commands
def cmd_add(a: argparse.Namespace) -> int:
    if a.endpoint:
        ep, password = endpoint.parse(a.endpoint)
        ep.module, ep.lease, ep.country = a.module, a.lease, a.country
    elif a.module:
        ep, password = _endpoint_from_module(a.module, lease=a.lease, country=a.country), None
    else:
        return _fail("give an ENDPOINT, or --module NAME to have a provider produce one")
    try:
        expose, expose_password = _expose_from_args(a)
        dns_cfg = _dns_from_args(a)
    except ValueError as exc:
        return _fail(str(exc))
    ex = exits.create(
        a.name,
        ep,
        password=password,
        dns=dns_cfg,
        expose=expose,
        expose_password=expose_password,
        notes=a.notes or "",
    )
    if a.socks_auth:
        ex.socks_auth = a.socks_auth
        exits.save(ex)
    if a.json:
        return _json(_exit_dict(ex))
    _p(f"added {ex.name} ({ex.id[:8]}) -> {ex.endpoint.label}")
    if ex.expose:
        _p(f"  host SOCKS5 at {ex.expose.address} once up")
    _p(f"  bring it up: kiwi-proxy up {ex.name}")
    return 0


def cmd_list(a: argparse.Namespace) -> int:
    found = exits.list_exits()
    if a.json:
        return _json([_exit_dict(ex) for ex in found])
    if not found:
        _p("no exits yet — add one: kiwi-proxy add NAME socks5://host:port")
        return 0
    for ex in found:
        _p(_exit_line(ex))
    return 0


def cmd_show(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    if a.json:
        return _json(_exit_dict(ex))
    _p(_exit_line(ex))
    _p(f"  id        {ex.id}")
    _p(f"  gateway   {paths.gateway_name(ex.id)}")
    _p(
        f"  endpoint  {ex.endpoint.label}{' (user ' + ex.endpoint.username + ')' if ex.endpoint.username else ''}"
    )
    if ex.endpoint.module:
        _p(
            f"  module    {ex.endpoint.module} lease={ex.endpoint.lease} country={ex.endpoint.country}"
        )
    if ex.socks_auth != "inject":
        _p(
            f"  socks     {ex.socks_auth} (clients' own SOCKS auth goes upstream behind the exit token)"
        )
    _p(f"  dns       {ex.dns.mode} via {ex.dns.upstream} · {', '.join(ex.dns.blocklists)}")
    if ex.expose:
        auth = f"user {ex.expose.username}" if ex.expose.username else "no password"
        _p(f"  host      socks5://{ex.expose.address} ({auth})")
    if ex.last_exit:
        e = ex.last_exit
        _p(f"  last exit {e.ip} {e.country or '?'} {e.city or ''} ({e.seen:%Y-%m-%d %H:%M})")
    if ex.owner:
        _p(f"  owner     {ex.owner}")
    return 0


def cmd_set(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    if a.endpoint:
        ep, password = endpoint.parse(a.endpoint)
        ep.module, ep.lease, ep.country = (
            a.module or ex.endpoint.module,
            a.lease or ex.endpoint.lease,
            a.country or ex.endpoint.country,
        )
        ex.endpoint = ep
        secrets.clear(ex.id, kind="endpoint")
        if password:
            secrets.store(ex.id, password, kind="endpoint")
    elif a.module or a.lease or a.country:
        module = a.module or ex.endpoint.module
        if not module:
            return _fail("--lease/--country need a module-backed exit (or --module)")
        ex.endpoint = _endpoint_from_module(
            module, lease=a.lease or ex.endpoint.lease, country=a.country or ex.endpoint.country
        )
    try:
        if a.no_expose:
            ex.expose = None
            secrets.clear(ex.id, kind="expose")
        elif a.expose:
            ex.expose, expose_password = _expose_from_args(a)
            secrets.clear(ex.id, kind="expose")
            if expose_password:
                secrets.store(ex.id, expose_password, kind="expose")
        ex.dns = _dns_from_args(a, ex.dns)
    except ValueError as exc:
        return _fail(str(exc))
    if a.notes is not None:
        ex.notes = a.notes
    if a.socks_auth:
        ex.socks_auth = a.socks_auth
    exits.save(ex)
    _p(
        f"{ex.name} saved"
        + (" — `kiwi-proxy up --replace` applies it now" if gateway.is_up(ex.id) else "")
    )
    return 0


def cmd_rm(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    if ex.owner and not a.force:
        return _fail(f"{ex.name} belongs to {ex.owner}; remove it there, or pass --force")
    gateway.down(ex.id)
    exits.delete(ex.id)
    _p(f"removed {ex.name}")
    return 0


def cmd_up(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    try:
        gw = gateway.up(ex, replace=a.replace, keep=True, measure=not a.no_measure)
    except gateway.GatewayError as exc:
        return _fail(str(exc))
    if a.json:
        return _json(gw.as_dict())
    _p(f"{ex.name} {'already up' if gw.reused else 'up'} — gateway {gw.name}")
    for note in gw.notes:
        _p(f"  {note}")
    if gw.info:
        _p(f"  exit      {gw.info.ip} {gw.info.country or ''} {gw.info.city or ''}".rstrip())
    _p(f"  join      podman run --network {gw.network} …   (SOCKS5 {gw.forwarder})")
    if gw.resolv_conf:
        _p(
            f"            with --volume {gw.resolv_conf}:/etc/resolv.conf:ro,z  (resolver {gw.resolver})"
        )
    if gw.expose:
        _p(f"  host      socks5h://{gw.expose}")
    _p(f"  stays up until: kiwi-proxy down {ex.name}")
    return 0


def cmd_down(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    members = podman.dependents(paths.gateway_name(ex.id))
    gateway.down(ex.id)
    gone = f" (and {', '.join(members)})" if members else ""
    _p(f"{ex.name} down{gone}")
    return 0


def cmd_name(a: argparse.Namespace) -> int:
    _p(paths.gateway_name(exits.resolve_ref(a.ref).id))
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    name = paths.gateway_name(ex.id)
    if not podman.is_running(name):
        return _fail(f"{ex.name} is not up; kiwi-proxy up {ex.name}")
    try:
        info = gateway.measure_exit(name)
    except gateway.GatewayError as exc:
        return _fail(f"{ex.name}: {exc}")
    exits.record_exit(ex, info)
    if a.json:
        return _json(info.model_dump(mode="json"))
    _p(f"{ex.name}: {info.ip} {info.country or '?'} {info.city or ''} {info.asn or ''}".rstrip())
    return 0


def cmd_test(a: argparse.Namespace) -> int:
    ep, password = endpoint.parse(a.endpoint)
    info = endpoint.preflight(ep, password)
    if a.json:
        return _json(info.model_dump(mode="json"))
    _p(f"exit {info.ip} {info.country or '?'} {info.city or ''} {info.timezone or ''}".rstrip())
    return 0


def cmd_ps(a: argparse.Namespace) -> int:
    rows = gateway.running()
    if a.json:
        return _json(rows)
    if not rows:
        _p("no gateways")
        return 0
    names = {e.id: e.name for e in exits.list_exits()}
    for r in rows:
        exit_name = names.get(r["exit_id"] or "", r["exit_id"] or "?")
        extra = " · ".join(
            x
            for x in (
                r["app"] if r["app"] != paths.APP else "",
                f"{r['module']}" + (f":{r['lease']}" if r["lease"] else "") if r["module"] else "",
                f"host {r['expose']}" if r["expose"] else "",
            )
            if x
        )
        _p(f"{r['name']:20} {r['state'] or '?':8} {exit_name:16} {extra}".rstrip())
    return 0


def cmd_reap(a: argparse.Namespace) -> int:
    cleaned = gateway.reap()
    _p(", ".join(cleaned) + " torn down" if cleaned else "nothing orphaned")
    return 0


def cmd_dns(a: argparse.Namespace) -> int:
    if a.dns_cmd == "sync":
        found = dns.sync_stamps()
        _p(f"{len(found)} resolver stamps cached")
        return 0
    names = a.names or ["oisd-big"]
    for name in names:
        path = dns.fetch_blocklist(name)
        _p(f"{name}: {sum(1 for _ in path.open())} entries")
    used = sorted({b for ex in exits.list_exits() for b in ex.dns.blocklists} | set(names))
    merged = dns.merged_blocklist(used)
    _p(f"merged {', '.join(used)} -> {merged}")
    return 0


def _module_status_line(name: str) -> tuple[str, bool]:
    try:
        prov, manifest = providers.load(name)
    except providers.ProviderError as exc:
        return f"{name:12} broken: {exc}", False
    ctx = providers.context_for(name, manifest)
    status = prov.status(ctx)
    missing = [b for b in prov.requirements() if not shutil.which(b)]
    img = "image yes" if status.image_present else "image MISSING (run `kiwi-proxy module setup`)"
    run = "running" if status.running else "idle"
    req = f" · missing: {', '.join(missing)}" if missing else ""
    ok = status.image_present and not missing
    return f"{name:12} {img} · {run}{req}", ok


def cmd_module(a: argparse.Namespace) -> int:
    cmd = a.module_cmd
    if cmd == "list":
        names = providers.discover()
        if getattr(a, "json", False):
            out = []
            for name in names:
                try:
                    out.append(json.loads(providers.manifest_of(name).model_dump_json()))
                except providers.ProviderError as exc:
                    out.append({"name": name, "error": str(exc)})
            return _json(out)
        if not names:
            _p("no provider modules installed")
            _p("install one, e.g.: kiwi install kiwi-plugin-tor")
            return 0
        for name in names:
            try:
                _prov, manifest = providers.load(name)
            except providers.ProviderError as exc:
                _p(f"{name:12} (broken: {exc})")
                continue
            acct = " · account required" if manifest.needs_account else ""
            desc = f" — {manifest.description}" if manifest.description else ""
            _p(f"{name:12} {manifest.title}{desc}{acct}")
        return 0
    if cmd == "status":
        line, _ok = _module_status_line(a.name)
        _p(line)
        return 0
    if cmd == "leases":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        leases = prov.leases(ctx)
        if not leases:
            _p(f"{a.name}: no selectable leases (the default exit is used)")
            return 0
        for lease in leases:
            loc = " ".join(x for x in (lease.country, lease.city) if x)
            _p(f"{lease.id:20} {lease.label or ''} {loc} {lease.detail or ''}".rstrip())
        return 0
    if cmd == "up":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        ep = prov.up(ctx, lease=a.lease, country=a.country)
        lease = f" --lease {a.lease}" if a.lease else ""
        _p(f"{a.name} up — provider SOCKS5 {ep.host}:{ep.port} on {paths.PROVIDERS_NETWORK}")
        _p(f"  make an exit of it: kiwi-proxy add <name> --module {a.name}{lease}")
        return 0
    if cmd == "down":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        prov.down(ctx, lease=a.lease)
        _p(f"{a.name} down")
        return 0
    if cmd == "setup":
        from . import setup

        try:
            setup.setup_module(a.name, progress=lambda m: _p(f"  {m}"))
        except setup.SetupError as exc:
            return _fail(str(exc))
        _p(f"{a.name}: image ready")
        return 0
    if cmd == "doctor":
        names = providers.discover()
        if not names:
            _p("no provider modules installed")
            return 0
        ok = True
        for name in names:
            line, line_ok = _module_status_line(name)
            _p(line)
            ok &= line_ok
        return 0 if ok else 1
    return _fail(f"unknown module command {cmd!r}")


def cmd_setup(a: argparse.Namespace) -> int:
    from . import setup

    try:
        steps = setup.run(progress=lambda m: _p(f"  {m}"))
    except setup.SetupError as exc:
        return _fail(str(exc))
    _p("")
    for step in steps:
        _p(f"  {step}")
    _p("\nReady — add an exit with `kiwi-proxy add <name> <endpoint>`")
    return 0


def cmd_doctor(a: argparse.Namespace) -> int:
    from . import setup

    ok = True
    _p(f"podman        {podman.version() if podman.available() else 'MISSING'}")
    ok &= podman.available()
    store = secrets.backend()
    _p(
        f"secrets       {'keyring (secret-tool)' if store == 'keyring' else f'files in {paths.secrets_dir()}'}"
    )
    stamps = dns.load_stamps()
    _p(f"dns stamps    {len(stamps) or 'none — run `kiwi-proxy dns sync`'}")
    blocklist = paths.blocklists_dir() / "blocked-names.txt"
    _p(f"blocklist     {blocklist if blocklist.exists() else 'none — run `kiwi-proxy dns update`'}")
    for image, name in setup.IMAGES:
        state = setup.image_state(image, name) if podman.available() else "missing"
        note = {
            "current": "yes",
            "stale": "outdated — built by an earlier version; run `kiwi-proxy setup`",
            "missing": "MISSING — run `kiwi-proxy setup`",
        }[state]
        _p(f"image         {image} {note}")
        ok &= state != "missing"
    _p(f"exits         {len(exits.list_exits())}")
    _p(f"modules       {', '.join(providers.discover()) or 'none'}")
    return 0 if ok else 1


# -------------------------------------------------------------------- parser
def _endpoint_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--module", help="a provider module that produces the endpoint (tor, vpn, …)")
    p.add_argument("--lease", help="which of the module's exits (see `module leases`)")
    p.add_argument("--country", help="two-letter code, when the module can target one")


def _expose_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--expose",
        metavar="[ADDR:]PORT",
        help="also publish the SOCKS5 on the host (default address 127.0.0.1)",
    )
    p.add_argument("--expose-user", help="demand this user (and a password) on the host port")
    p.add_argument(
        "--expose-password-stdin", action="store_true", help="read that password from stdin"
    )
    p.add_argument(
        "--expose-open",
        action="store_true",
        help="allow a non-loopback host port without a password",
    )


def _dns_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--dns", choices=("resolver", "remote"), help="resolver in the gateway, or at the proxy"
    )
    p.add_argument("--upstream", help=f"DoH upstream: {', '.join(dns.UPSTREAMS)}")
    p.add_argument("--blocklist", action="append", help=f"one of {', '.join(dns.BLOCKLISTS)}")
    p.add_argument(
        "--socks-auth",
        choices=("inject", "passthrough"),
        help="passthrough: carry a client's own SOCKS auth (Tor Browser's per-site circuits)",
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kiwi-proxy",
        description="Sealed SOCKS5/VPN exits in rootless Podman, for browsers, tools and hosts",
    )
    ap.add_argument("--version", action="version", version=f"kiwi-proxy {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ad = sub.add_parser("add", help="add an exit")
    ad.add_argument("name")
    ad.add_argument(
        "endpoint", nargs="?", help="socks5://user:pass@host:port, host:port[:user:pass]"
    )
    _endpoint_args(ad)
    _expose_args(ad)
    _dns_args(ad)
    ad.add_argument("--notes")
    ad.add_argument("--json", action="store_true")
    ad.set_defaults(func=cmd_add)

    ls = sub.add_parser("list", help="list exits")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=cmd_list)

    sh = sub.add_parser("show", help="everything about one exit")
    sh.add_argument("ref")
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(func=cmd_show)

    se = sub.add_parser("set", help="change an exit")
    se.add_argument("ref")
    se.add_argument("--endpoint")
    _endpoint_args(se)
    _expose_args(se)
    se.add_argument("--no-expose", action="store_true", help="stop publishing it on the host")
    _dns_args(se)
    se.add_argument("--notes")
    se.set_defaults(func=cmd_set)

    rm = sub.add_parser("rm", help="remove an exit")
    rm.add_argument("ref")
    rm.add_argument("--force", action="store_true", help="also one another app created")
    rm.set_defaults(func=cmd_rm)

    up = sub.add_parser("up", help="bring an exit's gateway up (headless) and keep it up")
    up.add_argument("ref")
    up.add_argument("--replace", action="store_true", help="restart it even if it is up")
    up.add_argument("--no-measure", action="store_true", help="skip measuring the exit")
    up.add_argument("--json", action="store_true")
    up.set_defaults(func=cmd_up)

    dn = sub.add_parser("down", help="tear an exit's gateway down, with whoever joined it")
    dn.add_argument("ref")
    dn.set_defaults(func=cmd_down)

    nm = sub.add_parser("name", help="print the gateway container to join (--network container:)")
    nm.add_argument("ref")
    nm.set_defaults(func=cmd_name)

    ck = sub.add_parser("check", help="measure what the world sees through a running exit")
    ck.add_argument("ref")
    ck.add_argument("--json", action="store_true")
    ck.set_defaults(func=cmd_check)

    t = sub.add_parser("test", help="probe an endpoint without creating anything")
    t.add_argument("endpoint")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=cmd_test)

    ps = sub.add_parser("ps", help="list gateways, whichever app started them")
    ps.add_argument("--json", action="store_true")
    ps.set_defaults(func=cmd_ps)

    sub.add_parser("reap", help="tear down gateways nobody uses").set_defaults(func=cmd_reap)

    dn_ = sub.add_parser("dns", help="resolver stamps and blocklists")
    dsub = dn_.add_subparsers(dest="dns_cmd", required=True)
    dsub.add_parser("sync", help="cache DoH resolver stamps")
    du = dsub.add_parser("update", help="download blocklists")
    du.add_argument("names", nargs="*")
    dn_.set_defaults(func=cmd_dns)

    sub.add_parser(
        "setup", help="build the gateway image, fetch DNS data, prepare modules"
    ).set_defaults(func=cmd_setup)
    sub.add_parser("doctor", help="check the environment").set_defaults(func=cmd_doctor)

    m = sub.add_parser("module", help="manage provider modules (tor, vpn, 9proxy, mysterium)")
    msub = m.add_subparsers(dest="module_cmd", required=True)
    mli = msub.add_parser("list", help="installed provider modules")
    mli.add_argument("--json", action="store_true")
    ms = msub.add_parser("status", help="a module's live state")
    ms.add_argument("name")
    ml = msub.add_parser("leases", help="selectable exits a module offers")
    ml.add_argument("name")
    mu = msub.add_parser("up", help="bring a provider up and print its address")
    mu.add_argument("name")
    mu.add_argument("--lease")
    mu.add_argument("--country")
    mdn = msub.add_parser("down", help="stop a provider")
    mdn.add_argument("name")
    mdn.add_argument("--lease")
    mse = msub.add_parser("setup", help="build or pull a module's image")
    mse.add_argument("name")
    msub.add_parser("doctor", help="check installed provider modules")
    m.set_defaults(func=cmd_module)
    return ap


def main(argv: list[str] | None = None) -> int:
    paths.ensure_tree()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (
        exits.ExitError,
        endpoint.EndpointError,
        podman.PodmanError,
        gateway.GatewayError,
        providers.ProviderError,
    ) as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
