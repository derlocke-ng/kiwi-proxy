# Consumers

What an application using kiwi-proxy can rely on. Two ways in: the Python package
(`kiwi_proxy`, for apps in the same process — kiwi-fox) and the CLI with `--json`
(for anything else — kiwi-pentesting, scripts). Both see the same exits and the
same gateways.

## The contract

- A gateway is a container named `paths.gateway_name(exit_id)` (`kf-gw-<id[:12]>`).
  Join it with `--network container:<name>`. A member has no network namespace of
  its own.
- Inside: SOCKS5 at **`127.0.0.1:1080`** (no auth for members), and in resolver mode
  a DNS resolver at **`127.0.0.2:53`**. A member has its own mount namespace, so it
  mounts `Gateway.resolv_conf` at `/etc/resolv.conf` (`--dns` cannot be combined
  with `--network container:`). In remote mode there is no resolver: use
  `socks5h` so names go to the exit.
- **Fail closed.** If the gateway dies, members lose connectivity. "Not running" is
  a hard stop for a consumer, never a reason to fall back to a direct connection.
- Credentials are podman secrets; a consumer never reads or needs them.
- Every gateway carries `kiwi-proxy.role=gateway` and `kiwi-proxy.exit=<exit id>`;
  `app` and any further labels are the consumer's own.

## Python

`install.sh` puts the package at `$KIWI_PREFIX/lib/kiwi-proxy` (default
`~/.local/lib/kiwi-proxy`); a consumer's launcher adds that to `PYTHONPATH`. In a
checkout, a sibling `../kiwi-proxy/src` does the same for tests.

```python
from kiwi_proxy import exits, gateway
from kiwi_proxy.models import DnsConfig, Endpoint

# Register an exit under your own id, so you find it again without a lookup table
# and the gateway keeps a name others already know.
ex = exits.create(
    "work", Endpoint(host="10.64.0.1", port=1080), exit_id=profile.id, owner="kiwi-fox"
)

gw = gateway.up(
    ex,
    password=my_keyring_lookup(),           # or None: kiwi-proxy's own secret store
    labels={"app": "kiwi-fox", "kiwi-fox.profile": profile.id, "kiwi-fox.role": "gateway"},
)
gw.name          # "kf-gw-…": --network container:<this>
gw.resolv_conf   # mount at /etc/resolv.conf, or None in remote DNS mode
gw.info          # ExitInfo measured on the host or through the gateway, or None
gw.reused        # True: it was already up with these settings (someone else uses it)
gw.notes         # human-readable lines worth showing

gateway.release(ex.id, ignore=(my_container,))   # done; gone unless still used or held
gateway.down(ex.id)                               # gone, with everyone inside
```

| Call | Use |
| --- | --- |
| `exits.create / load / save / list_exits / resolve_ref / delete` | the store |
| `gateway.up(ex, *, password, expose_password, labels, replace, keep, measure)` | bring up / reuse |
| `gateway.release(exit_id, *, ignore)` / `gateway.down(exit_id)` | let go / tear down |
| `gateway.is_up(exit_id)`, `gateway.running()` | state; `running()` lists every gateway with its labels |
| `gateway.measure_exit(name)` | the exit as the world sees it, from inside |
| `gateway.plan(ex, password, measure=)` | the upstream without starting anything (pre-flight) |
| `gateway.gateway_spec(...)`, `gateway.write_resolv_conf(ex)` | building blocks, for a consumer with special needs |
| `gateway.reap()`, `gateway.reconcile()` | housekeeping, safe at any time |
| `endpoint.parse(spec)` | `socks5://…`, `host:port:user:pass` → `(Endpoint, password)` |
| `providers.*` | modules: `discover`, `load`, `context_for`, `manages` |
| `setup.run(progress)` | build the gateway image, DNS data, module images |

Errors: `exits.ExitError`, `gateway.GatewayError`, `endpoint.EndpointError` (alias
`ProxyError`), `providers.ProviderError`, `podman.PodmanError`.

The exit's `socks_auth` decides what the forwarder does with a member's own SOCKS
credentials: `inject` (default) answers no-auth; `passthrough` carries Tor Browser's
per-site credentials upstream behind the exit's token.

## CLI

```
kiwi-proxy list --json           [{id, name, endpoint, dns, expose, owner, gateway, running, held, …}]
kiwi-proxy show NAME --json      one of those
kiwi-proxy up NAME --json        {exit_id, name, network, forwarder, resolver, resolv_conf, expose, info, reused, notes}
kiwi-proxy name NAME             the gateway container, for --network container:
kiwi-proxy check NAME --json     {ip, country, city, timezone, asn, seen}
kiwi-proxy ps --json             [{name, exit_id, state, app, module, lease, expose}]
kiwi-proxy down NAME
```

`up` from the CLI holds the exit (it stays until `down`), which is what a headless
consumer wants: kiwi-pentesting brings an identity's exit up without a browser,
runs its tools in it, and downs it.

## kiwi-fox

kiwi-fox registers one exit per profile (`exit_id=profile.id`, `owner="kiwi-fox"`),
so its gateways keep the names and isolation tokens they always had. It brings the
exit up at launch, joins the browser, and calls `release(profile.id,
ignore=(browser,))` when the window closes — a pentest tool on the same identity, or
a `kiwi-proxy up` of it, keeps the exit alive. Its launch-time pre-flight
(`gateway.plan`) still decides the fingerprint's region before the window opens.

## kiwi-pentesting

It drives the CLI (`core/proxyclient.py`, `docs/kiwi-proxy-integration.md` there):

- `kiwi-proxy list --json` for every exit, including ones with no browser, and
  `kiwi-proxy ps --json` / the `kiwi-proxy.role=gateway` label for running gateways
  from any app; kiwi-fox's own labels (`kiwi-fox.role=gateway`, `kiwi-fox.profile`)
  are its fallback;
- `kiwi-proxy up <name> --json` to bring an identity up headless, then `name` to
  join; `kiwi-proxy down <name>` when done;
- `kiwi-proxy check <name> --json` to measure the exit without a probe container
  of its own.

## Something on the host

No API at all: `kiwi-proxy add NAME … --expose PORT`, `kiwi-proxy up NAME`, and point
the application at `socks5h://127.0.0.1:PORT`.
