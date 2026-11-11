"""kiwi-proxy command line. Consumers use the Python API or `--json`; the CLI is the truth."""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import sys

from . import (
    __version__,
    dns,
    endpoint,
    exits,
    gateway,
    paths,
    podman,
    prefs,
    providers,
    secrets,
    selection,
    snapshots,
)
from .models import DnsConfig, Exit, Expose
from .snapshots import items as snapshot_items


def _p(*args: object) -> None:
    print(*args)


def _fail(msg: str) -> int:
    print(f"kiwi-proxy: {msg}", file=sys.stderr)
    return 1


def _json(payload: object) -> int:
    print(json.dumps(payload, indent=2, default=str))
    return 0


# ------------------------------------------------------------------ helpers
_endpoint_from_module = exits.module_endpoint


def _module_endpoint(module: str, *, lease, country, base=None):
    """A module endpoint from the command line. For a module that takes several
    countries (Tor), --country is a list of them and goes to its Only list."""
    if selection.supports(module):
        ep = _endpoint_from_module(module, lease=lease, country=None)
        if base is not None and base.module == module:
            ep.only_countries = list(base.only_countries) or (
                [base.country.upper()] if base.country else []
            )
            ep.only_nodes = list(base.only_nodes)
            ep.never_countries = list(base.never_countries)
        if country is not None:
            ep.only_countries = list(selection.clean([country]))
        return ep
    if country and "," in country:
        raise ValueError(f"{module} exits in one country at a time")
    return _endpoint_from_module(module, lease=lease, country=country)


def _apply_lists(ep, a) -> None:
    """--never and --node, for a module that takes them; then check the lot."""
    never, nodes = getattr(a, "never", None), getattr(a, "node", None)
    if never is None and nodes is None and not selection.supports(ep.module):
        return
    if not selection.supports(ep.module):
        raise ValueError("--never and --node are for Tor exits (a module that takes them)")
    if never is not None:
        ep.never_countries = list(selection.clean([never]))
    if nodes is not None:
        ep.only_nodes = list(selection.clean_nodes(nodes))
    sel = selection.of(ep)
    if sel and (problems := sel.problems()):
        raise ValueError("; ".join(problems))


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
    try:
        ex = exits.make_expose(
            bind, port, username=a.expose_user, password=password, allow_open=a.expose_open
        )
    except ValueError as exc:
        raise ValueError(f"{exc} (--expose-user, or --expose-open)") from exc
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
    cfg = (base or prefs.new_exit_dns()).model_copy()
    if getattr(a, "dns", None):
        cfg.mode = a.dns
    if getattr(a, "upstream", None):
        if a.upstream not in dns.UPSTREAMS:
            raise ValueError(f"unknown upstream {a.upstream!r}; one of {', '.join(dns.UPSTREAMS)}")
        cfg.upstream = a.upstream
    if getattr(a, "no_blocklist", False):
        cfg.blocklists = []
    elif getattr(a, "blocklist", None):
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
        try:
            ep, password = _module_endpoint(a.module, lease=a.lease, country=a.country), None
        except ValueError as exc:
            return _fail(str(exc))
    else:
        return _fail("give an ENDPOINT, or --module NAME to have a provider produce one")
    try:
        _apply_lists(ep, a)
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
    note = snapshot_items.auto_exit(ex)
    if a.json:
        return _json(_exit_dict(ex))
    _p(f"added {ex.name} ({ex.id[:8]}) -> {ex.endpoint.label}")
    if ex.expose:
        _p(f"  host SOCKS5 at {ex.expose.address} once up")
    _p(f"  bring it up: kiwi-proxy up {ex.name}")
    if note:
        _p(f"  {note}")
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
        if (sel := selection.of(ex.endpoint)) is not None:
            _p(f"  module    {ex.endpoint.module}")
            _p(f"  only      {', '.join([*sel.only_countries, *sel.only_nodes]) or "Tor's choice"}")
            _p(f"  never     {', '.join(sel.own_never) or '-'}")
            if group := set(sel.never_countries) - set(sel.own_never):
                _p(f"  and never {', '.join(sorted(group))} (Preferences, every Tor exit)")
        else:
            _p(
                f"  module    {ex.endpoint.module} lease={ex.endpoint.lease} "
                f"country={ex.endpoint.country}"
            )
    if ex.socks_auth != "inject":
        _p(
            f"  socks     {ex.socks_auth} (clients' own SOCKS auth goes upstream behind the exit token)"
        )
    adblock = ", ".join(ex.dns.blocklists) if ex.dns.blocklists else "off"
    _p(f"  dns       {ex.dns.mode} via {ex.dns.upstream} · ad-blocking {adblock}")
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
    elif a.module or a.lease or a.country is not None or a.never is not None or a.node is not None:
        module = a.module or ex.endpoint.module
        if not module:
            return _fail("--lease/--country/--never/--node need a module-backed exit (or --module)")
        try:
            ex.endpoint = _module_endpoint(
                module,
                lease=a.lease or ex.endpoint.lease,
                country=a.country
                if a.country is not None
                else (None if selection.supports(module) else ex.endpoint.country),
                base=ex.endpoint,
            )
            _apply_lists(ex.endpoint, a)
        except ValueError as exc:
            return _fail(str(exc))
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
        + (f" — `kiwi-proxy up --replace {ex.name}` applies it now" if gateway.is_up(ex.id) else "")
    )
    if note := snapshot_items.auto_exit(ex):
        _p(f"  {note}")
    return 0


def _print_logs(entries: list[tuple[str, str]]) -> None:
    for i, (name, text) in enumerate(entries):
        if i:
            _p("")
        _p(f"==> {name} <==")
        _p(text.rstrip() or "(no output yet)")


def cmd_logs(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    entries = gateway.exit_logs(ex, lines=a.lines)
    if not entries:
        return _fail(f"{ex.name} has no running containers; `kiwi-proxy up {ex.name}` first")
    _print_logs(entries)
    return 0


def cmd_rm(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    if ex.owner and not a.force:
        return _fail(f"{ex.name} belongs to {ex.owner}; remove it there, or pass --force")
    gateway.down(ex.id)
    exits.delete(ex.id)
    _p(f"removed {ex.name}")
    return 0


def _newer_snapshot_note(ex: Exit) -> str | None:
    """A line when the snapshot folder holds a newer copy of the exit than this
    device's; nothing when snapshots are not set up, locked, or say nothing new."""
    s = snapshots.load_settings()
    if s is None or not s.ask_older:
        return None
    try:
        rel = snapshots.relation(snapshot_items.EXIT, ex.id, here=True)
    except (snapshots.SnapshotError, OSError):
        return None
    if not rel.newer_elsewhere:
        return None
    return f"{rel.describe()}: kiwi-proxy snapshot restore {ex.name}"


def cmd_up(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    if note := _newer_snapshot_note(ex):
        print(f"kiwi-proxy: {note}", file=sys.stderr)
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
    kept = {m: gateway.kept_as(m) for m in members}
    gateway.down(ex.id)
    gone = ", ".join(f"{m} (kept as {kept[m]})" if kept[m] else m for m in members)
    _p(f"{ex.name} down" + (f" (and {gone})" if gone else ""))
    return 0


def cmd_name(a: argparse.Namespace) -> int:
    _p(paths.gateway_name(exits.resolve_ref(a.ref).id))
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    ex = exits.resolve_ref(a.ref)
    name = paths.gateway_name(ex.id)
    if podman.is_running(name) and gateway.provider_alive(ex) is False:
        return _fail(
            f"{ex.name}: its provider container is gone (the tunnel gave up); "
            f"`kiwi-proxy logs {ex.name}` says why, `kiwi-proxy up --replace {ex.name}` restarts it"
        )
    try:
        info = gateway.probe(ex)
    except (gateway.GatewayError, providers.ProviderError, endpoint.EndpointError) as exc:
        return _fail(f"{ex.name}: {exc}")
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
    healed = gateway.heal()
    for line in healed:
        _p(line if ": " in line else f"{line}: provider restarted behind it")
    cleaned = gateway.reap()
    for name in cleaned:
        _p(f"{name} torn down")
    if not healed and not cleaned:
        _p("nothing orphaned")
    return 0


def cmd_prefs(a: argparse.Namespace) -> int:
    """What a new exit starts with (DNS), and the Eyes group no Tor exit uses."""
    p = prefs.load()
    changed = False
    if a.upstream:
        if a.upstream not in dns.UPSTREAMS:
            return _fail(f"unknown upstream {a.upstream!r}; one of {', '.join(dns.UPSTREAMS)}")
        p.new_exit_upstream, changed = a.upstream, True
    if a.no_blocklist:
        p.new_exit_blocklists, changed = [], True
    elif a.blocklist:
        if unknown := [b for b in a.blocklist if b not in dns.BLOCKLISTS]:
            return _fail(f"unknown blocklist {unknown}; one of {', '.join(dns.BLOCKLISTS)}")
        p.new_exit_blocklists, changed = list(a.blocklist), True
    if a.tor_never is not None:
        p.tor_never_group, changed = ("" if a.tor_never == "none" else a.tor_never), True
    if changed:
        prefs.save(p)
    group = selection.EYES.get(p.tor_never_group, ())
    _p(f"new exits resolve through  {p.new_exit_upstream}")
    _p(f"new exits block            {', '.join(p.new_exit_blocklists) or 'nothing'}")
    _p(
        f"no Tor exit leaves through {selection.EYES_TITLES[p.tor_never_group]}"
        + (f" ({', '.join(group)})" if group else "")
    )
    if changed and a.tor_never is not None:
        _p("Tor exits brought up from now on follow it; running ones at their next start")
    return 0


def cmd_storage(a: argparse.Namespace) -> int:
    """Podman's quick storage check; with --repair, remove what is broken."""
    from . import storage

    if a.storage_cmd == "leftovers":
        found = storage.leftovers(a.app)
        gone = storage.remove([c.name for c in found]) if a.remove else []
        for c in found:
            _p(f"{c.name:40} {c.state}{'  removed' if c.name in gone else ''}")
        if not found:
            _p("none")
        return 0
    report = storage.check()
    if report.error:
        return _fail(f"could not check: {report.error}")
    if report.ok:
        _p("podman's storage is fine")
        return 0
    _p("podman's storage is damaged")
    for c in report.broken:
        _p(f"  {c.name:40} {c.app or 'not kiwi'}")
    if report.layers and not report.broken:
        _p(f"  {len(report.layers)} damaged layer(s) no container uses")
    if a.storage_cmd != "repair":
        _p("kiwi-proxy storage repair removes the kiwi ones (--theirs-too: the others as well)")
        return 1
    names = [c.id for c in report.ours] + ([c.id for c in report.others] if a.theirs_too else [])
    if not a.yes:
        listed = [c.name for c in report.broken if c.id in names] or ["no container"]
        answer = input(f"remove {', '.join(listed)} and repair? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            _p("nothing changed")
            return 1
    after = storage.repair(report, names)
    _p("repaired: podman's storage is fine" if after.ok else "still damaged:")
    for c in after.broken:
        _p(f"  {c.name:40} {c.app or 'not kiwi'}")
    return 0 if after.ok else 1


def cmd_dns(a: argparse.Namespace) -> int:
    if a.dns_cmd == "sync":
        found = dns.sync_stamps()
        _p(f"{len(found)} resolver stamps cached")
        return 0
    # Every list an exit uses, not only the default: the daily timer runs this
    # with no arguments and must keep each exit's own lists fresh.
    sets = {tuple(sorted(dns.DEFAULT_BLOCKLISTS))}
    sets |= {tuple(sorted(ex.dns.blocklists)) for ex in exits.list_exits()}
    if a.names:
        sets.add(tuple(sorted(a.names)))
    failed = 0
    for name in a.names or sorted({n for s in sets for n in s}):
        try:
            path = dns.fetch_blocklist(name)
        except Exception as exc:  # noqa: BLE001 - one list down must not stop the others
            print(f"kiwi-proxy: {name}: {exc}", file=sys.stderr)
            failed += 1
            continue
        _p(f"{name}: {sum(1 for _ in path.open())} entries")
    for names in sorted(sets):
        merged = dns.merged_blocklist(list(names))
        _p(f"merged {', '.join(names) or '(none)'} -> {merged.name}")
    return 1 if failed else 0


def _module_status_line(name: str) -> tuple[str, bool]:
    try:
        prov, manifest = providers.load(name)
    except providers.ProviderError as exc:
        return f"{name:12} broken: {exc}", False
    ctx = providers.context_for(name, manifest)
    status = prov.status(ctx)
    missing = [b for b in prov.requirements() if not shutil.which(b)]
    img = (
        "image yes"
        if status.image_present
        else f"image MISSING (run `kiwi-proxy module setup {name}`)"
    )
    run = "running" if status.running else "idle"
    req = f" · missing: {', '.join(missing)}" if missing else ""
    cfg = ""
    if prov.settings(ctx):
        state = prov.configured(ctx)
        cfg = f" · {state}" if state else f" · not configured (kiwi-proxy module config {name})"
    ok = status.image_present and not missing
    return f"{name:12} {img} · {run}{req}{cfg}", ok


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
        leases = providers.leases_for(prov, ctx, a.country)
        if not leases:
            where = f" in {a.country.upper()}" if a.country else ""
            _p(f"{a.name}: no selectable leases{where} (the default exit is used)")
            return 0
        shown = [
            x
            for x in leases
            if (not a.kind or (x.kind or "") == a.kind) and (not a.search or x.matches(a.search))
        ]
        width = max((len(x.id) for x in shown), default=0)
        for lease in shown:
            loc = " ".join(x for x in (lease.country, lease.city) if x)
            bits = [lease.kind or lease.label, loc, lease.isp, lease.detail]
            _p(f"{lease.id:{width}}  " + "  ".join(b for b in bits if b))
        tail = f"{len(shown)} of {len(leases)}" if len(shown) != len(leases) else f"{len(leases)}"
        _p(
            f"{tail} {providers.plural(providers.lease_noun_of(prov), len(leases))}"
            + (" — the picker in the app filters the same way" if len(leases) > 40 else "")
        )
        return 0
    if cmd == "nodes":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        found = list(getattr(prov, "nodes", lambda _c: [])(ctx))
        if not found:
            _p(f"{a.name} offers no relays to choose from")
            return 0
        blocked = set(selection.blocked_everywhere())
        want = a.country.upper() if a.country else None
        text = (a.search or "").lower()
        shown = [
            n
            for n in found
            if n.country not in blocked
            and (not want or n.country == want)
            and (not text or text in f"{n.name} {n.operator} {n.fingerprint}".lower())
        ]
        for n in shown[: a.limit]:
            _p(
                f"{n.fingerprint}  {n.country}  {n.speed / 1048576:5.0f} MiB/s  {n.name}  {n.operator}"
            )
        _p(
            f"{min(len(shown), a.limit)} of {len(shown)} relays"
            + (
                f" (the {len(found) - len(shown)} others are filtered or blocked)"
                if len(shown) != len(found)
                else ""
            )
        )
        return 0
    if cmd == "countries":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        found = providers.countries_for(prov, ctx)
        own = bool(getattr(prov, "countries", lambda _c: [])(ctx))
        for c in found:
            _p(f"{c.code}  {c.name}" + (f"  {c.count}" if c.count is not None else ""))
        _p(
            f"{len(found)} countries"
            + ("" if own else f" — {a.name} does not say where it can exit; any of these")
        )
        return 0
    if cmd == "logs":
        if not podman.available():
            return _fail("podman is not installed")
        rows = [
            (c.get("Names") or [""])[0]
            for c in podman.ps(labels={paths.MODULE_LABEL: a.name})
            if (c.get("Labels") or {}).get(paths.ROLE_LABEL) in ("provider", "tunnel", "adapter")
        ]
        if not rows:
            _p(f"no {a.name} container is running")
            return 0
        _print_logs([(n, podman.logs(n, tail=a.lines)) for n in rows])
        return 0
    if cmd == "settings":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        settings = prov.settings(ctx)
        if not settings:
            _p(f"{a.name}: nothing to configure")
            return 0
        for st in settings:
            need = "" if st.required else " (optional)"
            _p(f"{st.key:14} {st.title}{need} [{st.kind}]")
            if st.help:
                _p(f"{'':14} {st.help}")
        state = prov.configured(ctx)
        _p(f"state: {state or 'not configured'}")
        _p(
            f"set them: kiwi-proxy module config {a.name} KEY=VALUE … "
            "(--ask KEY prompts for a password)"
        )
        return 0
    if cmd == "config":
        prov, manifest = providers.load(a.name)
        ctx = providers.context_for(a.name, manifest)
        known = {st.key: st for st in prov.settings(ctx)}
        if not known:
            return _fail(f"{a.name}: nothing to configure")
        values: dict[str, str] = {}
        for item in a.values:
            key, sep, value = item.partition("=")
            if not sep or key not in known:
                return _fail(f"{item!r}: expected KEY=VALUE with KEY one of {', '.join(known)}")
            values[key] = value
        for key in a.ask or []:
            if key not in known:
                return _fail(f"--ask {key}: not a setting of {a.name} ({', '.join(known)})")
            import getpass

            values[key] = getpass.getpass(f"{known[key].title}: ")
        missing = [k for k, st in known.items() if st.required and k not in values]
        if missing:
            return _fail(f"missing: {', '.join(missing)} (kiwi-proxy module settings {a.name})")
        for line in prov.configure(ctx, values):
            _p(f"  {line}")
        if note := snapshot_items.auto_module(a.name):
            _p(f"  {note}")
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
    snap = snapshots.status()
    if snap.missing_tools:
        _p(f"snapshots     need {' and '.join(snap.missing_tools)} (everything else works)")
    elif snap.settings is None:
        _p("snapshots     not set up — kiwi-proxy snapshot setup FOLDER")
    else:
        state = "unlocked" if snap.unlocked else "locked — kiwi-proxy snapshot unlock"
        where = "" if snap.folder_present else " (folder not there)"
        _p(f"snapshots     {snap.settings.folder}{where}, {state}")
    return 0 if ok else 1


# ----------------------------------------------------------------- snapshots
_APP_OF_KIND = {"profile": "Kiwi Fox", "box": "Kiwi Custodia"}


def _read_passphrase(a: argparse.Namespace, prompt: str, *, confirm: bool = False) -> str:
    """From stdin (one line) with --passphrase-stdin, else asked unechoed."""
    if getattr(a, "passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass(prompt)
    if confirm and getpass.getpass("Again: ") != first:
        raise snapshots.SnapshotError("the two passphrases differ")
    return first


def _snapshot_ref(ref: str) -> tuple[str, str, str, bool]:
    """(kind, item, name, here) for an exit name or id, or module:NAME; an exit that
    is not on this device is looked up in the folder."""
    if ref.startswith("module:"):
        name = ref.split(":", 1)[1]
        return snapshot_items.MODULE, name, name, snapshot_items.module_has_state(name)
    try:
        ex = exits.resolve_ref(ref)
        return snapshot_items.EXIT, ex.id, ex.name, True
    except exits.ExitError:
        kind, item, name = snapshot_items.find_in_folder(ref)
        return kind, item, name, False


def _snap_line(meta: snapshots.Meta) -> str:
    aside = " · kept before a restore" if meta.aside else ""
    return (
        f"{meta.id}  {snapshots.when_text(meta.created):20} {meta.device:12} "
        f"{snapshots.size_text(meta.size):>8}{aside}"
    )


def cmd_snapshot(a: argparse.Namespace) -> int:
    cmd = a.snapshot_cmd
    if cmd == "setup":
        from pathlib import Path

        folder = Path(a.folder).expanduser()
        joining = snapshots.Folder.at(folder.absolute()) is not None
        if joining:
            secret = _read_passphrase(a, "Passphrase of the snapshot folder: ")
        else:
            _p(f"A new snapshot folder. Choose a passphrase of at least {snapshots.MIN_PASSPHRASE}")
            _p("characters; every device needs it once, and without it nothing in the folder")
            _p("can be read. It cannot be recovered.")
            secret = _read_passphrase(a, "Passphrase: ", confirm=True)
        s, created = snapshots.setup(
            folder, secret, device_name=a.device, remember=not a.no_remember
        )
        _p(f"{'made' if created else 'joined'} {s.folder} as {s.device_name}")
        if not a.no_remember:
            _p("  the passphrase is kept in this device's keyring")
        if created:
            _p("  add the folder to your sync client (Nextcloud) to have it on other devices")
            _p("  kiwi-proxy snapshot now   takes the first snapshots of your exits")
        return 0
    if cmd == "status":
        st = snapshots.status()
        if st.settings is None:
            _p("not set up — kiwi-proxy snapshot setup FOLDER")
            return 0
        s = st.settings
        _p(f"folder     {s.folder}{'' if st.folder_present else '  (not there)'}")
        _p(f"device     {s.device_name}")
        _p(f"state      {'unlocked' if st.unlocked else 'locked — kiwi-proxy snapshot unlock'}")
        _p(f"automatic  {'on' if s.automatic else 'off'}   keep {s.keep} per item")
        _p(f"ask first  {'yes' if s.ask_older else 'no'} before using an older copy")
        if st.missing_tools:
            _p(f"missing    {', '.join(st.missing_tools)}")
        return 0
    if cmd == "unlock":
        secret = _read_passphrase(a, "Passphrase of the snapshot folder: ")
        snapshots.unlock(secret, remember=not a.no_remember)
        _p("unlocked" + ("" if a.no_remember else " — kept in this device's keyring"))
        return 0
    if cmd == "lock":
        snapshots.lock()
        _p("locked — the passphrase is no longer kept on this device")
        return 0
    if cmd == "set":
        s = snapshots.load_settings()
        if s is None:
            return _fail("not set up — kiwi-proxy snapshot setup FOLDER")
        if a.keep is not None:
            if not 1 <= a.keep <= snapshots.MAX_KEEP:
                return _fail(f"--keep takes 1 to {snapshots.MAX_KEEP}")
            s.keep = a.keep
        if a.automatic is not None:
            s.automatic = a.automatic == "on"
        if a.ask_older is not None:
            s.ask_older = a.ask_older == "on"
        if a.device:
            s.device_name = a.device
        snapshots.save_settings(s)
        _p(
            f"saved: keep {s.keep}, automatic {'on' if s.automatic else 'off'}, device {s.device_name}"
        )
        return 0
    if cmd == "list":
        cat = snapshots.catalog()
        local = snapshot_items.local_items()
        folder_id = snapshots.folder().id
        rows = []
        for key in sorted(set(cat) | set(local), key=lambda k: (k[0], (cat.get(k) or [None])[0])):
            kind, item = key
            metas = cat.get(key, [])
            name = local.get(key) or (metas[0].name if metas else item)
            if kind in _APP_OF_KIND:
                state = f"({_APP_OF_KIND[kind]})"
            else:
                rel = snapshots.relation(
                    kind, item, here=key in local, metas=metas, folder_id=folder_id
                )
                state = rel.describe()
            newest = (
                f"{metas[0].device}, {snapshots.when_text(metas[0].created)} · {len(metas)} kept"
                if metas
                else ""
            )
            rows.append((kind, name, state, newest))
        if not rows:
            _p("nothing in the snapshot folder yet — kiwi-proxy snapshot now")
            return 0
        width = max(len(r[1]) for r in rows)
        state_width = max(len(r[2]) for r in rows)
        for kind, name, state, newest in rows:
            _p(f"{kind:8} {name:{width}}  {state:{state_width}}  {newest}".rstrip())
        return 0
    if cmd == "now":
        targets = (
            [_snapshot_ref(r) for r in a.refs]
            if a.refs
            else [(k, i, n, True) for (k, i), n in sorted(snapshot_items.local_items().items())]
        )
        if not targets:
            _p("nothing to snapshot yet: no exits, no module settings")
            return 0
        for kind, item, name, here in targets:
            if not here:
                return _fail(f"{name} is not on this device")
            if kind == snapshot_items.EXIT:
                meta = snapshot_items.take_exit(exits.load(item))
            else:
                meta = snapshot_items.take_module(item)
            _p(f"{kind} {name}: snapshot taken ({snapshots.size_text(meta.size)})")
        return 0
    if cmd == "history":
        kind, item, name, _here = _snapshot_ref(a.ref)
        metas = snapshots.history(kind, item)
        if not metas:
            _p(f"no snapshot of {name} yet")
            return 0
        for meta in metas:
            _p(_snap_line(meta))
        return 0
    if cmd == "restore":
        kind, item, name, here = _snapshot_ref(a.ref)
        if a.id:
            sid = a.id
        else:
            rel = snapshots.relation(kind, item, here=here)
            if rel.head is None:
                return _fail(f"no snapshot of {name} in the folder")
            sid = rel.head.id
            if here and rel.state == "same":
                _p(f"{name} is the newest snapshot already")
                return 0
        if here and not a.yes:
            if not sys.stdin.isatty():
                return _fail(f"{name} is on this device; restoring replaces it — pass --yes")
            answer = input(f"Replace this device's {name} with snapshot {sid[:8]}? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                _p("nothing changed")
                return 1
        if kind == snapshot_items.EXIT:
            restored = snapshot_items.restore_exit(item, sid)
            _p(f"restored exit {restored.name}")
        else:
            snapshot_items.restore_module(item, sid)
            _p(f"restored the settings of module {item}")
        if here:
            _p("  what was here is kept as a snapshot: kiwi-proxy snapshot history " + a.ref)
        return 0
    if cmd == "forget":
        kind, item, name, _here = _snapshot_ref(a.ref)
        if not a.yes:
            return _fail(f"this deletes every snapshot of {name} from the folder — pass --yes")
        removed = snapshots.forget(kind, item)
        _p(f"deleted {removed} snapshot(s) of {name}")
        return 0
    return _fail(f"unknown snapshot command {cmd}")


def _snapshot_parser(sub) -> None:
    sn = sub.add_parser(
        "snapshot", help="encrypted snapshots of exits and module settings, for other devices"
    )
    ssub = sn.add_subparsers(dest="snapshot_cmd", required=True)

    def passphrase_args(p) -> None:
        p.add_argument(
            "--passphrase-stdin", action="store_true", help="read the passphrase from stdin"
        )
        p.add_argument(
            "--no-remember", action="store_true", help="do not keep it in this device's keyring"
        )

    st = ssub.add_parser("setup", help="choose the snapshot folder: make a new one or join one")
    st.add_argument("folder")
    st.add_argument("--device", help="what this device is called in snapshots (default: hostname)")
    passphrase_args(st)
    ssub.add_parser("status", help="folder, device, locked or not")
    un = ssub.add_parser("unlock", help="enter the passphrase on this device")
    passphrase_args(un)
    ssub.add_parser("lock", help="forget the passphrase on this device")
    se = ssub.add_parser("set", help="change how snapshots are taken")
    se.add_argument("--keep", type=int, help=f"snapshots kept per item, 1 to {snapshots.MAX_KEEP}")
    se.add_argument("--automatic", choices=("on", "off"), help="snapshot an exit when it changes")
    se.add_argument(
        "--ask-older", choices=("on", "off"), help="warn before using a copy the folder has newer"
    )
    se.add_argument("--device", help="what this device is called in snapshots")
    ssub.add_parser("list", help="everything in the snapshot folder, and how it relates to here")
    nw = ssub.add_parser("now", help="snapshot exits and module settings now")
    nw.add_argument("refs", nargs="*", metavar="REF", help="an exit, or module:NAME; default all")
    hi = ssub.add_parser("history", help="the snapshots of one exit (or module:NAME)")
    hi.add_argument("ref")
    rs = ssub.add_parser("restore", help="restore an exit (or module:NAME) from the folder")
    rs.add_argument("ref")
    rs.add_argument("--id", help="which snapshot (see history); default the newest")
    rs.add_argument("--yes", action="store_true", help="replace this device's copy without asking")
    fg = ssub.add_parser("forget", help="delete every snapshot of an exit from the folder")
    fg.add_argument("ref")
    fg.add_argument("--yes", action="store_true")
    sn.set_defaults(func=cmd_snapshot)


def _endpoint_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--module", help="a provider module that produces the endpoint (tor, vpn, …)")
    p.add_argument("--lease", help="which of the module's exits (see `module leases`)")
    p.add_argument(
        "--country",
        help="two-letter code (`module countries NAME`); for Tor a list to exit through only: de,se",
    )
    p.add_argument(
        "--never", metavar="CODES", help="Tor: countries never to exit through: hu,tr ('' clears)"
    )
    p.add_argument(
        "--node",
        action="append",
        metavar="FINGERPRINT",
        help="Tor: a relay to exit through only (repeatable, `module nodes tor`; '' clears)",
    )


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
    p.add_argument(
        "--blocklist",
        action="append",
        help=f"ad-blocking list, repeatable: {', '.join(dns.BLOCKLISTS)} (default oisd-big)",
    )
    p.add_argument("--no-blocklist", action="store_true", help="no ad-blocking for this exit")
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

    lg = sub.add_parser("logs", help="recent logs of an exit's containers (provider, gateway)")
    lg.add_argument("ref")
    lg.add_argument("--lines", type=int, default=200, help="how many lines per container")
    lg.set_defaults(func=cmd_logs)

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
    pf = sub.add_parser("prefs", help="what new exits start with; the Eyes group Tor never uses")
    pf.add_argument("--upstream", help=f"new exits resolve through: {', '.join(dns.UPSTREAMS)}")
    pf.add_argument("--blocklist", action="append", help="new exits block these (repeatable)")
    pf.add_argument("--no-blocklist", action="store_true")
    pf.add_argument("--tor-never", choices=("none", "five", "nine", "fourteen"))
    pf.set_defaults(func=cmd_prefs)
    st = sub.add_parser("storage", help="check podman's storage, repair it, remove leftovers")
    stsub = st.add_subparsers(dest="storage_cmd", required=True)
    stsub.add_parser("check", help="podman system check --quick, with names")
    sr = stsub.add_parser("repair", help="remove broken containers and repair")
    sr.add_argument("--theirs-too", action="store_true", help="also containers that are not kiwi's")
    sr.add_argument("--yes", "-y", action="store_true")
    sl = stsub.add_parser("leftovers", help="an app's containers a crash left behind")
    sl.add_argument("--app", default="kiwi-proxy", help="kiwi-proxy, kiwi-fox or kiwi-custodia")
    sl.add_argument("--remove", action="store_true")
    st.set_defaults(func=cmd_storage)

    dn_ = sub.add_parser("dns", help="resolver stamps and blocklists")
    dsub = dn_.add_subparsers(dest="dns_cmd", required=True)
    dsub.add_parser("sync", help="cache DoH resolver stamps")
    du = dsub.add_parser("update", help="download blocklists")
    du.add_argument(
        "names",
        nargs="*",
        help=f"default: every list an exit uses; one of {', '.join(dns.BLOCKLISTS)}",
    )
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
    ml.add_argument("--country", help="only this country's, where the module can filter")
    ml.add_argument("--kind", help="only this IP type: residential, hosting, cellular, …")
    ml.add_argument("--search", help="any part of an id, a city, an ISP")
    mco = msub.add_parser("countries", help="where a module can exit, with counts where it knows")
    mco.add_argument("name")
    mno = msub.add_parser("nodes", help="the relays a module can exit through (Tor), fastest first")
    mno.add_argument("name")
    mno.add_argument("--country")
    mno.add_argument("--search", help="part of a name, a network or a fingerprint")
    mno.add_argument("--limit", type=int, default=40)
    mst = msub.add_parser("settings", help="what a module needs from you, and what it has")
    mst.add_argument("name")
    mcf = msub.add_parser("config", help="give a module its settings (a keystore, a passphrase)")
    mcf.add_argument("name")
    mcf.add_argument("values", nargs="*", metavar="KEY=VALUE")
    mcf.add_argument("--ask", action="append", metavar="KEY", help="prompt for KEY, unechoed")
    mu = msub.add_parser("up", help="bring a provider up and print its address")
    mu.add_argument("name")
    mu.add_argument("--lease")
    mu.add_argument("--country")
    mdn = msub.add_parser("down", help="stop a provider")
    mdn.add_argument("name")
    mdn.add_argument("--lease")
    mlg = msub.add_parser("logs", help="recent logs of a module's running containers")
    mlg.add_argument("name")
    mlg.add_argument("--lines", type=int, default=200)
    mse = msub.add_parser("setup", help="build or pull a module's image")
    mse.add_argument("name")
    msub.add_parser("doctor", help="check installed provider modules")
    m.set_defaults(func=cmd_module)

    _snapshot_parser(sub)
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
        snapshots.SnapshotError,
    ) as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
