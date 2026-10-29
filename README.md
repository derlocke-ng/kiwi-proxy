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

- **kiwi-fox** joins each browser identity to its exit's gateway.
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

## Use

```
kiwi-proxy add work socks5://user:pass@host:port   # a plain upstream
kiwi-proxy add tor-de --module tor --country de     # or one a module produces
kiwi-proxy add mullvad-se --module vpn --lease Sweden --expose 1081
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

### Tor Browser

Tor Browser puts a SOCKS username and password on every request to get a circuit
per site. `--socks-auth passthrough` carries them through, behind the exit's own
token, so Tor's `IsolateSOCKSAuth` keeps per-site circuits while exits stay apart.
kiwi-fox sets it for its Tor Browser profiles.

## Provider modules

Each module is its own kiwi app and exposes plain SOCKS5; the gateway reaches it
over a private bridge and still permits exactly one destination.

| Module | Repository | Upstream | Account |
| --- | --- | --- | --- |
| `tor` | kiwi-plugin-tor | the Tor network | no |
| `vpn` | kiwi-plugin-vpn | a WireGuard/OpenVPN tunnel (gluetun) | a VPN subscription |
| `9proxy` | kiwi-plugin-9proxy | 9proxy residential exits | yes |
| `mysterium` | kiwi-plugin-myst | the Mysterium dVPN | identity (free) |

```
kiwi install kiwi-plugin-vpn
kiwi-proxy module list            # `module leases vpn` for exits, `module doctor`
```

See [docs/plugin-system.md](docs/plugin-system.md) for how modules work and how to
write one.

## Documentation

- [docs/architecture.md](docs/architecture.md) — gateways, members, the host listener, providers
- [docs/consumers.md](docs/consumers.md) — the API kiwi-fox, kiwi-pentesting and others use
- [docs/plugin-system.md](docs/plugin-system.md) — the provider contract
- [docs/kiwi-server.md](docs/kiwi-server.md) — hosting exits on a node or the master
- [docs/decisions.md](docs/decisions.md) — why things are the way they are

## Requirements

Rootless Podman, Python 3.12+ with pydantic. `secret-tool` when there is a desktop
keyring. kiwi-server machines need only their stack runtime: they pull the gateway
image from `ghcr.io/derlocke-ng/kiwi-proxy/gateway`.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
