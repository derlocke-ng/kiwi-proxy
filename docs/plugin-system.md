# Provider plugin system

kiwi-proxy turns a chosen upstream into a sealed exit. *Where* the exit comes from
— a plain SOCKS5 you were given, the Tor network, a VPN tunnel, a residential-proxy
account, a Mysterium node — is the job of a **provider module**.

A provider module is a small, self-contained plugin, shipped in its own repository
and installed through kiwi-updater. kiwi-proxy discovers it, builds its container
image, brings it up on demand, and points an exit's gateway at it. The suite of
first-party modules:

| Module | Repository | Upstream | Account |
| --- | --- | --- | --- |
| `tor` | kiwi-plugin-tor | the Tor network | no |
| `vpn` | kiwi-plugin-vpn | a WireGuard/OpenVPN tunnel (gluetun) | yes (a VPN subscription) |
| `9proxy` | kiwi-plugin-9proxy | 9proxy residential exits | yes |
| `mysterium` | kiwi-plugin-myst | the Mysterium dVPN | identity (free) |

The contract lived in kiwi-fox until the proxy engine was split out; it is
unchanged except for the import path (`kiwi_fox.core.…` → `kiwi_proxy.…`), the
install directory, and the image names. The same exit serves every consumer:
kiwi-fox's browser, [kiwi-pentesting](https://github.com/derlocke-ng/kiwi-pentesting)'s
tool containers, host applications through a published port — browsing and testing
share one IP.

## The one rule

**Every provider exposes SOCKS5 and nothing else.** Adapting its upstream into
plain SOCKS5 is the module's job, so the gateway, the credential forwarder, the
single firewall rule and the DNS design stay one shape. A VPN tunnel that only
offers an HTTP proxy ships a tiny SOCKS5 adapter alongside it; a provider that
speaks SOCKS5 natively (Tor) needs none.

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
                                         browser joins the gateway netns
```

kiwi-proxy resolves the provider container's current bridge address every bring-up
(it can change across restarts) and passes that literal address to the gateway,
which permits exactly it. The kill switch is unchanged: if the gateway dies its
members lose their route; if the provider dies the gateway's one permitted
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
module's `DEPENDS=kiwi-proxy`) and usually subclasses `ContainerProvider`, which implements the
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

Module-level secrets that are not per-exit (a VPN WireGuard key, a 9proxy login)
are stored as their own podman secrets via `ctx.set_secret(...)` and mounted into
the provider container; `kiwi-proxy module setup <name>` is where a module collects
them.

## Using it

```sh
kiwi install kiwi-plugin-tor          # installs the module under modules_dir
kiwi-proxy setup                      # builds kiwi-proxy/tor:latest (among others)
kiwi-proxy module list                # installed modules
kiwi-proxy module leases tor          # selectable exits, if any
kiwi-proxy add tor-de --module tor --country de   # an exit the provider produces
kiwi-proxy up tor-de                  # brings the provider and the gateway up
kiwi-proxy module doctor              # image present? binaries present? running?
```

kiwi-fox does the same for a browser profile: `kiwi-fox new work --module tor
--country de` registers the exit with kiwi-proxy and launching the profile brings
it up.

A provider container is shared across every exit on the same module+lease — from
every consumer — and is torn down only when no running gateway still uses it.

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
- **A gateway whose provider address drifts is failed closed.** As a backstop,
  `gateway.reconcile()` (run from `reap()`) compares each running gateway's
  pinned `KF_ENDPOINT_IP` against its provider's current address and tears the
  gateway down on a mismatch — so the forwarder can never send traffic, or
  account credentials, to whatever else might hold that address.
- **The gateway does not carry `NET_RAW`.** nftables, the resolver and the forwarder
  use no raw sockets, so it is dropped from the gateway's `cap_add`; on the shared L2
  segment this removes an ARP-spoofing capability.

Still open, documented rather than closed:

- **`kf-providers` is one shared L2 segment** (it cannot be `--internal` — the
  provider needs its own egress). The nft default-drop is the barrier, the same as
  on pasta. Moving to a per-provider network (one bridge per module+lease, only the
  gateways using it attached) would shrink the segment further.
- The static-IP and reconcile paths need a live podman host to exercise end to end;
  the logic is unit-tested, but validate `module up` and a provider restart on a real
  machine.
