# kiwi-proxy

Sealed SOCKS5/VPN exits in rootless Podman — for browsers, pentest tools, host
applications and kiwi-server machines.

An **exit** is one upstream, by name: a SOCKS5 you were given, or one a provider
module produces for you — Tor, a VPN tunnel (gluetun), 9proxy, Mysterium. Bringing
it up makes a **gateway**: a network namespace whose only route is that upstream.

```
gateway container   owns the network namespace
                    nftables: default drop, one permitted destination
                    forwarder 127.0.0.1:1080: adds the upstream's credentials
                    dnscrypt-proxy 127.0.0.2:53: ad-blocking, upstream through the same exit
                    host listener :1081 (optional): the same SOCKS5, published on the host
members             join it with --network container:<gateway> — no routing table of their own
```

The kill switch is the absence of a route, not software that has to notice: if the
gateway dies, everything using it loses connectivity.

This is the proxy engine [kiwi-fox](https://github.com/derlocke-ng/kiwi-fox) used to
carry, split out so it serves more than one browser:

- **kiwi-fox** gives each browser profile an exit; several profiles may share one,
  and they share its gateway.
- **[kiwi-pentesting](https://github.com/derlocke-ng/kiwi-pentesting)** joins its tool
  containers to the same gateway — browsing and testing share one IP.
- **Anything on the host** — a browser, `curl`, a mail client — uses the exit's
  published SOCKS5. For people who juggle several VPNs: one exit per VPN, one local
  port each.
- **[kiwi-server](https://github.com/derlocke-ng/kiwi-server)** machines host exits for
  the whole mesh with the module in [`server-module/`](server-module/kiwi-proxy).

## Install

```
kiwi install kiwi-proxy      # or: ./install.sh install
kiwi-proxy setup             # gateway image, DNS data, provider module images
```

`kiwi install kiwi-fox` brings it along; kiwi-fox's own `setup` runs this one.

## The app

`kiwi-proxy-gui` ("Kiwi Proxy" in your app grid) does everything below without a
terminal: add and edit exits — a SOCKS5 you were given or a provider module — bring
them up and down, offer one as a SOCKS5 port on this computer and copy its address,
check what the world sees through it, see who joined a gateway, set up modules.

![Exits](data/screenshots/1-exits.png)

![A new exit](data/screenshots/2-new-exit.png)

![DNS and ad-blocking](data/screenshots/4-dns-adblock.png)

## Use

```
kiwi-proxy add work socks5://user:pass@host:port   # a plain upstream
kiwi-proxy add tor-de --module tor --country de     # or one a module produces
kiwi-proxy add home --module vpn --config ~/wg0.conf --expose 1081   # your own VPN
kiwi-proxy add us-1 --module 9proxy --country us   # a 9proxy residential IP
kiwi-proxy list
kiwi-proxy up mullvad-se          # headless: the gateway and nothing else, kept up
kiwi-proxy check mullvad-se       # what the world sees through it
kiwi-proxy down mullvad-se
```

Endpoint formats: `socks5://user:pass@host:port`, `http://…`, `https://…`, and the
vendor paste format `host:port:user:pass`. Passwords go to the Secret Service
(`secret-tool`), or to 0600 files on a machine without one.

### On the host

`--expose [ADDR:]PORT` publishes the exit's SOCKS5 on the host, `127.0.0.1` unless
you say otherwise. Point anything at `socks5h://127.0.0.1:1081` — the `h` sends
names to the exit too, so DNS does not leak around it.

```
kiwi-proxy add se socks5://10.64.0.1:1080 --expose 1081
kiwi-proxy add nl socks5://10.65.0.1:1080 --expose 1082
kiwi-proxy up se && kiwi-proxy up nl
curl --proxy socks5h://127.0.0.1:1082 https://ifconfig.co/json
systemctl --user enable --now kiwi-proxy@se     # up at every login
```

An address other machines can reach needs `--expose-user NAME` (you are asked for a
password; the listener then demands it), or `--expose-open` to say you mean it.

### Joining a gateway

```
kiwi-proxy up work --json   # {"name": "kf-gw-…", "network": "container:kf-gw-…", "forwarder": "127.0.0.1:1080", …}
podman run --rm --network "container:$(kiwi-proxy name work)" \
    docker.io/curlimages/curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.co/json
```

`kiwi-proxy ps` lists every gateway, whichever app started it. A gateway a consumer
brought up goes when the last member leaves; one brought up with `kiwi-proxy up`
stays until `kiwi-proxy down`.

### DNS and ad-blocking

By default an exit resolves names in its own gateway (dnscrypt-proxy, DoH through
the same exit), asking Quad9, Mullvad, Cloudflare and Google and using the fastest
that answers — one that is down costs nothing (`--upstream quad9,mullvad` for
fewer, or the switches in the app). It refuses names on its blocklists — oisd big unless you pick
others (`--blocklist oisd-small`, `--blocklist oisd-nsfw`, `--no-blocklist`, or the
switches in the app; Preferences → DNS sets what a new exit starts with). The
block applies wherever a name shows up:

| Who | How it is blocked |
| --- | --- |
| a container that joined the gateway | its resolver (`/etc/resolv.conf` → 127.0.0.2) answers REFUSED |
| an app on the host port with `socks5h://` | the forwarder refuses the CONNECT for that name |
| a kiwi-server exit | the gateway fetches its lists through its own exit, daily, and the forwarder refuses |

`--dns remote` hands every name to the exit untouched — no resolver in the
gateway, which is what Tor needs (`.onion` resolves only there). The forwarder
still refuses listed names, since a remote-DNS client hands it every one; so
ad-blocking holds in both modes, and `--no-blocklist` turns it off. An app using
plain `socks5://` (no `h`) resolves names itself, outside the exit: use
`socks5h`. The lists refresh daily (`kiwi-proxy-blocklists.timer`, or
`kiwi-proxy dns update`); running gateways pick the new list up by themselves.

### VPN exits (TCP and UDP)

`--module vpn --config FILE` takes your WireGuard `.conf` or OpenVPN `.ovpn` (keys
inside; in the app: Source vpn → Config: Choose…). The exit's own gluetun owns the
namespace: its firewall is the kill switch, its route the tunnel, and the gateway
joins it — so a Kiwi Custodia box there sends TCP and UDP through the VPN, and
nothing leaves when the tunnel is down. A WireGuard config must route `0.0.0.0/0`;
one key works in one place at a time, so an exit does not start while another is
up with its key. As many VPN exits as you like, each with its own tunnel.

### 9proxy: one daemon, ten exits

`kiwi-proxy module config 9proxy username=YOU --ask password` once; then each
`--module 9proxy` exit gets one of the daemon's ten ports, one residential IP each.
An exit starts on an IP from 9proxy's today's list (no new IP); a new one only when
you ask — `kiwi-proxy renew EXIT`, or New IP in the exit's details, which says it
uses one IP from your balance.

### Tor Browser

Tor Browser puts a SOCKS username and password on every request to get a circuit
per site. `--socks-auth passthrough` carries them through, behind the exit's own
token, so Tor's `IsolateSOCKSAuth` keeps per-site circuits while exits stay apart.
An exit on the tor module is passthrough by default: a member without SOCKS
credentials still gets the exit's token, so the same exit serves Tor Browser, a
Camoufox profile and a tool alike.

### Snapshots, for your other devices

Exits and module settings, passwords included, go into one encrypted folder that
your sync client (Nextcloud) carries to your other devices; Kiwi Fox and Kiwi
Custodia use the same folder. The passphrase is entered once per device and kept in
its keyring. Snapshots are taken when you add or change an exit, and on demand.

```bash
kiwi-proxy snapshot setup ~/Nextcloud/kiwi-snapshots
kiwi-proxy snapshot list
kiwi-proxy snapshot restore mullvad-se
```

In the app: Preferences (Ctrl+,) → Snapshots. See
[docs/snapshots.md](docs/snapshots.md), which also says how to open a snapshot by
hand with gpg.

## Provider modules

Each module is its own kiwi app. Most expose plain SOCKS5, which the gateway reaches
over a private bridge, permitting exactly one destination; a VPN is a tunnel the
gateway joins instead.

| Module | Repository | Upstream | Account |
| --- | --- | --- | --- |
| `tor` | kiwi-plugin-tor | the Tor network | no |
| `vpn` | kiwi-plugin-vpn | your WireGuard/OpenVPN config, TCP and UDP (gluetun) | your VPN |
| `9proxy` | kiwi-plugin-9proxy | 9proxy residential IPs, ten exits per account | yes |
| `mysterium` | kiwi-plugin-myst | the Mysterium dVPN | identity (free) |

```
kiwi install kiwi-plugin-vpn
kiwi-proxy module list            # `module leases vpn` for exits, `module doctor`
kiwi-proxy module config mysterium keystore=~/0x….json --ask passphrase   # what a module needs from you
kiwi-proxy module countries tor                                          # where a module can exit, with counts
kiwi-proxy module leases mysterium --country DE --kind residential      # providers there, best first (--search cbb6)
```

A module that needs something from you — Mysterium's identity keystore and its
passphrase — says so in `module settings NAME`; the app asks for the same under
*Provider modules → Configure…*.

See [docs/plugin-system.md](docs/plugin-system.md) for how modules work and how to
write one.

## Documentation

- [docs/architecture.md](docs/architecture.md) — gateways, members, the host listener, providers
- [docs/consumers.md](docs/consumers.md) — the API kiwi-fox, kiwi-pentesting and others use
- [docs/plugin-system.md](docs/plugin-system.md) — the provider contract
- [docs/snapshots.md](docs/snapshots.md) — snapshots for other devices: the folder, the encryption, which copy is newer
- [docs/kiwi-server.md](docs/kiwi-server.md) — hosting exits on a node or the master
- [docs/decisions.md](docs/decisions.md) — why things are the way they are

## Requirements

Rootless Podman, Python 3.12+ with pydantic. GTK 4 + libadwaita (PyGObject) for
the app. `secret-tool` when there is a desktop keyring. kiwi-server machines need only their stack runtime: they pull the gateway
image from `ghcr.io/derlocke-ng/kiwi-proxy/gateway`.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
