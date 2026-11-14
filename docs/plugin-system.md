# Writing a provider module

This page is for people who write a provider module, or want to know how one
works. kiwi-proxy turns a chosen upstream into a sealed exit. Where the
upstream comes from (the Tor network, a VPN tunnel, a residential proxy
account, a Mysterium node) is the job of a **provider module**. How you use the
existing modules is on the page [Provider modules](modules.md).

A provider module is a small plugin in its own repository, installed by
kiwi-updater like any other Kiwi app. kiwi-proxy finds it on disk, builds its
container image, starts it when an exit needs it, and points the exit's gateway
at it. The same exit then serves every app that uses kiwi-proxy: a kiwi-fox
browser, the tool containers of
[kiwi-pentesting](https://github.com/derlocke-ng/kiwi-pentesting), and programs
on the host through a published port.

The contract was part of kiwi-fox before the proxy engine became its own app.
Only the import path (`kiwi_fox.core.…` → `kiwi_proxy.…`), the install folder
and the image names changed.

## The one rule

**Every provider exposes SOCKS5 — or is a tunnel the gateway joins.** Adapting an
upstream into plain SOCKS5 is the module's job, so the gateway, the credential
forwarder, the single firewall rule and the DNS design stay one shape; a provider
that speaks SOCKS5 natively (Tor) needs nothing. The one exception is a VPN
(`joins="tunnel"`, below): it carries UDP, which SOCKS5 cannot, so the gateway
joins the tunnel's namespace instead of connecting to it.

## How a local provider is wired

A provider that runs its own container needs its own exit to the internet *and*
has to be reachable by the gateway that forwards into it. It cannot share the
gateway's network namespace — the gateway default-drops everything but one
destination, which would strand the provider's own upstream — so the two meet on a
shared podman bridge, `kf-providers`:

```
          kf-providers bridge (rootless)
   ┌──────────────┴───────────────┐
provider container            gateway container
(own exit to internet)        nftables: default drop,
SOCKS5 on <bridge-ip>:port    permit only <provider-ip>:port
                              forwarder 127.0.0.1:1080  ─┐
                              dnscrypt-proxy 127.0.0.2:53 │
                                                          ▼
                     members (a browser, a tool) join the gateway netns
```

kiwi-proxy resolves the provider container's current bridge address every bring-up
(it can change across restarts) and passes that literal address to the gateway,
which permits exactly it. The kill switch is unchanged: if the gateway stops, its
members lose their route; if the provider stops, the gateway's one permitted
destination stops answering.

A plain, already-remote SOCKS5 endpoint touches none of this — its gateway stays
on `pasta` and reaches the public address directly.

## What a module ships

Installed under `~/.local/share/kiwi-proxy/modules/<name>/`:

```
provider.py          exposes PROVIDER (a Provider) and MANIFEST (a ProviderManifest)
containers/
  Containerfile      the provider image, built at setup time as kiwi-proxy/<name>:latest
  entrypoint.sh      brings the upstream up and exposes SOCKS5
```

The module directory name is the module id — `tor`, `vpn`, `9proxy`, `mysterium` —
and must equal `MANIFEST.name`. It is loaded by file path, not by import name, so a
name that is not a legal Python identifier (`9proxy`) is fine.

## The contract

`provider.py` imports the contract from kiwi-proxy (a runtime prerequisite: the
module's `DEPENDS=kiwi-proxy podman`) and usually subclasses `ContainerProvider`, which implements the
whole container lifecycle. A module then declares only its manifest, its container
spec, and its leases:

```python
from kiwi_proxy.models import ContainerSpec, Lease, ProviderManifest
from kiwi_proxy.providers.base import ContainerProvider

MANIFEST = ProviderManifest(
    name="tor",
    title="Tor",
    description="exit through the Tor network",
    socks_port=9050,
    auth="isolation",      # none | isolation | account
    needs_account=False,
    requires=[],           # host binaries `module doctor` checks for
)


class TorProvider(ContainerProvider):
    manifest = MANIFEST

    def container_spec(self, ctx, *, lease=None, country=None):
        return ContainerSpec(
            name=ctx.container_name(lease),
            image=ctx.image,
            network=ctx.network,          # must attach to the providers bridge
            env={...},
            # kiwi-proxy.role / kiwi-proxy.module are added for you
        )

    def leases(self, ctx):
        return [Lease(id="de", country="DE"), ...]


PROVIDER = TorProvider()
```

`ContainerProvider` gives you `up()` (ensure the bridge, start the container, wait
for an address, return the live `Endpoint`), `down()`, `status()`, and `setup()`
(build the image from `containers/Containerfile`, or pull one named in the
manifest). Override `ready()` when the upstream has a slow handshake — a VPN tunnel
or a Tor bootstrap — so kiwi-proxy waits for the SOCKS5 port, not just a running
container.

### When a tunnel stops

A tunnel module's node that loses its session should fail closed and exit (a
`FATAL` line, then `exit 1`), not try to reconnect under its own kill switch.
kiwi-proxy notices the provider gone behind a running gateway (`gateway.heal`,
from the app's poll and `kiwi-proxy reap`) and starts the node and its adapter
again on the same static address; the gateway and its members keep their route.
Tunnel containers therefore get no podman restart policy — a restarted tunnel
would leave its adapter in the old namespace.

### Saying what went wrong

Log from your entrypoint with a fixed prefix (`kf-myst: connecting to …`,
`kf-myst: FATAL: …`) and declare it as `log_marker = "kf-myst:"` on the provider:
when a start times out or the container exits, kiwi-proxy quotes those lines in
its error instead of whatever the daemon printed last, and `kiwi-proxy logs NAME`
/ the app's View logs show the whole container log. A `FATAL` line is how a
tunnel module's `tunnel_ready` turns a dead end into an error with a reason.

### Settings

A module that needs something from the user before it can run — Mysterium's
identity keystore and its passphrase, an account token — declares it:

```python
from kiwi_proxy.providers.base import Setting

def settings(self, ctx):
    return [Setting("keystore", "Identity keystore", kind="file", help="…"),
            Setting("passphrase", "Keystore passphrase", kind="password", required=False)]

def configure(self, ctx, values):   # values: key -> file path / password / text
    ...                              # keep it in ctx.state_dir, ctx.set_secret(…)
    return ["identity 0x… imported"]  # lines worth showing

def configured(self, ctx):          # one line on the current state, or None
    return "identity 0x12…ab"
```

The app shows a **Configure…** button for such a module (a file chooser, an
unechoed password, a text field, as declared), and the CLI has
`kiwi-proxy module settings NAME` and `kiwi-proxy module config NAME KEY=VALUE …
--ask KEY`. `module status` and `module list` say when a module is not configured.

### Leases by country

`leases(ctx, *, country=None)` may filter: Mysterium has hundreds of providers
per country, so the picker asks for the country chosen, and `kiwi-proxy module
leases NAME --country DE` does the same. A module whose `leases(ctx)` takes no
country is called without one (`providers.leases_for`). Return every exit, not
a best-N: the picker narrows. Fill `kind` (the IP type: residential, hosting,
cellular, …), `quality` (higher is better; the picker sorts by it) and `isp`
where you know them — the picker's toggles, order and search use them, and
`Lease.short_id` / `Lease.matches(text)` are how ids are shown and searched.

### What a lease is called

A module may say what one of its leases is — `lease_noun = "node"` on the provider
class (Mysterium), `"server"` (a VPN), `"port"` (9proxy). The app's picker, the
exit editor and `kiwi-proxy module leases` then speak that language ("137 nodes to
choose from", a row titled *Node*, "Node id, 0xcbb6…eb78 for example"). Without it
a lease is an "exit".

### What a snapshot leaves out

A module's settings travel to the user's other devices in snapshots (see
[snapshots.md](snapshots.md)): its whole `ctx.state_dir` and its podman secrets.
`snapshot_exclude` on the provider class names what to leave out, as paths relative
to the state folder or shell patterns: anything the module rebuilds, and anything
a running container writes (a copy taken then could be torn). Mysterium leaves out
the node's database (`"myst/mainnet"`), Tor its country cache. Read with getattr:
an older kiwi-proxy ignores it.

### Countries

`countries(ctx)` says where a module can exit: `Country(code, name, count)`, the
count where the module knows it (Tor's running exit relays per country from the
Tor directory, Mysterium's providers per country from discovery). The exit editor
offers that as a searchable list with names and counts, and `kiwi-proxy module
countries NAME` prints it. A module that cannot say — or predates the hook —
returns nothing, and every country there is gets offered instead
(`kiwi_proxy.countries`, ISO 3166-1); `providers.countries_for` does both. A
country alone is a complete choice: Tor's `leases()` is empty, the country is the
whole selection, and a module that can filter gets it in `leases(ctx, country=…)`.

### Credentials

Three auth modes, handled by kiwi-proxy so the module never touches the keyring:

- **`none`** — the SOCKS5 takes no credentials.
- **`isolation`** — any user/pass is accepted and used only to separate circuits
  per exit. kiwi-proxy mints a stable per-exit token and the gateway forwarder
  sends it (Tor `IsolateSOCKSAuth`), so each exit gets its own circuit. With
  `socks_auth=passthrough` (Tor Browser) a member's own per-site credentials ride
  behind that token, so each site gets its own circuit too.
- **`account`** — fixed credentials you hold with the provider, given as the
  exit endpoint's own username/password and forwarded as usual.

Module-level configuration that is not per-exit — a VPN's WireGuard key, a 9proxy
login, a Mysterium identity — lives as files in the module's state directory,
`~/.local/share/kiwi-proxy/modules-state/<name>/` (`ctx.state_dir`), mounted
read-only into the provider container so it stays out of `podman inspect`; each
module's README says which files. `kiwi-proxy module setup <name>` only builds or
pulls the module's images. (`ctx.set_secret` / `ctx.secret_mount` exist for a
module that would rather keep a value as a podman secret; none of the first-party
modules does.)

### Tunnel modules (`joins="tunnel"`)

A module whose manifest says `joins="tunnel"` (kiwi-plugin-vpn: gluetun, one per
exit) creates the exit's network namespace. Its container's firewall is the kill
switch and its route the tunnel; the gateway starts with
`--network container:<tunnel>` and `KF_UPSTREAM=direct` (no nft flush, the
forwarder connects targets itself, the resolver rides the tunnel), and members get
TCP and UDP. A host port (`--expose`) has to be published on the tunnel container
(podman publishes only on a namespace's owner): `gateway.expose_publish(exit)`
gives the `--publish`, and the module labels its container with
`kiwi-proxy.expose` so kiwi-proxy starts the tunnel again when the port changes.
`gateway.is_tunnel(exit)` tells consumers (Kiwi Custodia leaves its tun2socks out).

A module can say something about a running container on the exit: the labels
`kiwi-proxy.note` (a few words) and `kiwi-proxy.note-help` (the why, behind a (?))
show in the exit's details, `kiwi-proxy show` and `kiwi-proxy up` while it runs
(`gateway.provider_note(exit)`). kiwi-plugin-vpn says when it fitted a WireGuard
config's MTU to the path.

### Options per exit

`exit_options(ctx) -> list[Setting]` makes a module offer more to choose an exit
by than its country: kiwi-plugin-9proxy returns state, city, zip code and plan,
the filters of 9proxy's own command. The exit dialog shows a text row for each
`Setting`, and `kiwi-proxy add` and `set` take `--opt KEY=VALUE`. kiwi-proxy
stores the values in the exit's endpoint (`options`, written only when set) and
passes them as `options=` to the module's `up` and `renew` when those methods
have that parameter.

### A config file per exit

`check_config(text) -> str` makes a module take one (`--config FILE`, the app's
Config row): it returns a few words on the file or raises `ProviderError` saying
why it cannot be an exit. kiwi-proxy keeps the text as the exit's secret (kind
`vpnconfig`, keyed by the exit, which becomes the lease) and forgets it with the
exit. `config_server(text) -> (host, port)` labels the exit by its server.

### One container for several leases; leases handed out; new IPs

- `container_for(ctx, lease) -> name`: the container serving a lease, when it is
  not one per lease (9proxy: one daemon, ten ports). kiwi-proxy asks
  `providers.container_of` everywhere it looks for a provider's container.
- `alive(ctx, lease) -> bool`: is the lease served (a 9proxy port still bound to an
  IP), not only its container running; `providers.lease_alive` and `heal` use it.
- `assign_lease(ctx, taken) -> lease`: each new exit gets the next free lease (a
  port); raise `ProviderError` when there is none.
- `renew(ctx, *, lease, country) -> lines`: a new IP on request (`kiwi-proxy renew`,
  New IP in the app, which first says it costs one IP).

## Try a module

```bash
kiwi install kiwi-plugin-tor          # installs the module under modules_dir
kiwi-proxy setup                      # builds kiwi-proxy/tor:latest (among others)
kiwi-proxy module list                # installed modules
kiwi-proxy module leases tor          # selectable exits, if any
kiwi-proxy add tor-de --module tor --country de   # an exit the provider produces
kiwi-proxy up tor-de                  # brings the provider and the gateway up
kiwi-proxy module doctor              # image present? binaries present? running?
```

kiwi-fox does the same for a browser profile: `kiwi-fox new work --module tor
--country de` registers the exit with kiwi-proxy, and opening the profile
brings it up.

A provider container is shared by every exit on the same module and lease,
whichever app uses it. A Tor container is shared by the exits that ask for the
same countries and relays. kiwi-proxy stops a provider container only when no
running gateway uses it any more.

## Hardening on the shared bridge

The leak-proof guarantee for a managed provider rests on the gateway's nftables
default-drop, exactly as for a plain endpoint; the leak suite asserts it on the
bridge (`tests/leak/test_network.py`), including that a non-permitted on-link
neighbour is still dropped. On top of that:

- **Providers get a deterministic static address.** `kf-providers` is created with a
  fixed subnet (`paths.PROVIDERS_SUBNET`) and each provider is assigned a stable IP
  derived from its module+lease, so it always returns to the same address and a
  freed address cannot be handed to a different container. The provider also runs
  with `--restart on-failure`, so an out-of-band crash recovers in place on that IP.
- **A tunnel container runs unlabelled.** SELinux's `container_t` may not open
  `/dev/net/tun` (Fedora denies it to the container type whatever the caps), so a
  spec that lists that device is rendered with `--security-opt label=disable`,
  unless it sets a label itself; dropped caps, `no-new-privileges` and the user
  namespace stay. Containers without the device keep the default labelling.
- **A gateway whose provider address drifts is failed closed.** As a backstop,
  `gateway.reconcile()` (run from `reap()`) compares each running gateway's
  pinned `KF_ENDPOINT_IP` against its provider's current address and tears the
  gateway down on a mismatch — so the forwarder can never send traffic, or
  account credentials, to whatever else might hold that address.
- **The gateway does not carry `NET_RAW`.** nftables, the resolver and the forwarder
  use no raw sockets, so it is dropped from the gateway's `cap_add`; on the shared L2
  segment this removes an ARP-spoofing capability.

Known gaps:

- **`kf-providers` is one shared L2 segment** (it cannot be `--internal` — the
  provider needs its own egress). The nft default-drop is the barrier, the same as
  on pasta. Moving to a per-provider network (one bridge per module+lease, only the
  gateways using it attached) would shrink the segment further.
- The static-IP and reconcile paths need a live podman host to exercise end to end;
  the logic is unit-tested, but validate `module up` and a provider restart on a real
  machine.
