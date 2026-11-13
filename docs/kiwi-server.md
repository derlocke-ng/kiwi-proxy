# kiwi-proxy on a kiwi-server machine

A kiwi-server node or master can host exits for the whole mesh, the private
WireGuard network that connects your kiwi-server machines and devices. Each
exit is a kiwi-proxy gateway, built from the same image with the same sealed
network namespace, and its SOCKS5 is published on the host's mesh address.
Devices in the mesh point a browser or a tool at
`socks5h://<host mesh address>:<port>`.

**Status.** The module has not been run on a machine yet. It is checked only
by a unit test that renders a host with kiwi-server's own renderer (see
[Development](development.md#tests)).

## Install the module

The module is
[`server-module/kiwi-proxy`](https://github.com/derlocke-ng/kiwi-proxy/tree/main/server-module/kiwi-proxy),
written in kiwi-server's module format: a `module.yaml` and a compose
template. It is not part of
[kiwi-server](https://kiwi-network.eu/docs/server/) or kiwi-modules yet. Until
it is, copy the folder into kiwi-server's `modules/` folder, into
kiwi-modules', or into the folder that `KIWI_MODULES_HOME` names:

```bash
cp -r ~/.local/lib/kiwi-proxy/server-module/kiwi-proxy ../kiwi-server/modules/
```

The machine pulls the gateway image `ghcr.io/derlocke-ng/kiwi-proxy/gateway`,
which `.github/workflows/images.yml` publishes. Nothing of kiwi-proxy itself is
installed on the machine.

## Configure a host

Add `kiwi-proxy` to a host's modules in the fleet file and list its exits:

```yaml
hosts:
  papaya:
    role: node
    node:
      vpn_ip: 10.8.0.25
      modules: [vpn-client, tor, kiwi-proxy]
      tor: { socks_policy_accept: "10.8.0.0/16,172.128.0.0/24" }   # let the stack network in
      kiwi-proxy:
        exits:
          mullvad-se: { host: 10.64.0.1, port: 1080, expose: 1081 }
          resi:       { host: proxy.example.net, port: 1080, username: u1, password: "…",
                        expose: 1082, expose_user: me, expose_password: "…" }
          tor:        { via: tor, port: 9050, expose: 1083 }
```

Each exit takes these keys:

| Key | Meaning |
|---|---|
| `host` and `port` | The upstream SOCKS5. A host name is resolved once, inside the gateway, before its firewall closes. |
| `via` and `port` | Instead of `host`: another module of this host's stack, reached at its address on the stack network, for example `tor`. |
| `expose` | The host port the exit's SOCKS5 is published on. Required. |
| `username`, `password` | The upstream's credentials. |
| `expose_user`, `expose_password` | The user and password the host port demands. |
| `ip` | The gateway's own address on the stack network. By default the exits take `.200`, `.201` and so on, from `ip_offset`. |
| `adblock` | `false` turns ad-blocking off for this exit. |

Settings of the module:

| Setting | Default | Meaning |
|---|---|---|
| `bind` | the host's mesh address (`vpn_ip`) | The host address the exits are published on. `127.0.0.1` keeps them on the host. |
| `open_firewall` | `true` | Opens the exit ports in the host's firewall. |
| `adblock` | `true` | Refuses names on the blocklists. |
| `blocklist_urls` | oisd small | The blocklists, separated by spaces. |
| `ip_offset` | `200` | The first host address on the stack network that the exits use. |
| `image` | `ghcr.io/derlocke-ng/kiwi-proxy/gateway:latest` | The gateway image. |

## Ad-blocking on a server

Nothing on the machine downloads blocklists. Each gateway downloads the lists
in `blocklist_urls` itself, through its own exit, after its firewall is up.
It repeats this once a day, and every ten minutes until the first download
works. Its forwarder then refuses connections to the listed names and to every
name under them. Each gateway keeps its list in memory, which is why the small
list is the default here.

## What the module creates

The module creates one service per exit, as a quadlet (a systemd unit for a
Podman container) or in a compose file. Its name is `kn-proxy-<exit name>` on
a node and `km-proxy-<exit name>` on the master. Each service:

- drops every capability except `NET_ADMIN` and `NET_BIND_SERVICE`, and runs
  with `no-new-privileges`;
- has a fixed address on the stack network and publishes its port on `bind`;
- reads its credentials from one file for all of the host's exits,
  `<docker_dir>/kn-proxy/credentials` (`km-proxy` on the master), owned by root
  with mode 0600 and mounted read-only. Each gateway reads its own row by its
  exit name. No password is in a unit file or in the environment;
- uses remote DNS: names go to the upstream, so clients must use `socks5h`.
  The forwarder still refuses listed names when `adblock` is on.

## Notes

- kiwi-server's `tor` module accepts SOCKS clients only from the networks in
  `socks_policy_accept`, by default the mesh. Add the stack network, as in the
  example, so that a `via: tor` gateway is let in.
- Provider modules (the kiwi-plugin-* apps) work only on a desktop with Podman
  and do not run here. On a server the upstream is a remote SOCKS5 proxy or a
  module of the stack, such as `tor` or the SOCKS5 proxy of a gluetun
  `vpn-client`.
- The exits do not go through the master's reverse proxy or DNS. They are plain
  TCP ports on the host's mesh address.
