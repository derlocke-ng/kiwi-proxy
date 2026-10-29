# kiwi-proxy on a kiwi-server machine

A node or the master can host exits for the whole mesh: each exit is a kiwi-proxy
gateway — the same image, the same sealed namespace — whose SOCKS5 is published on
the host's mesh address. Mesh clients point a browser or a tool at
`socks5h://<host mesh address>:<port>`.

The module is [`server-module/kiwi-proxy`](../server-module/kiwi-proxy), in
kiwi-server's module format (`module.yaml` + compose template). It is not in
kiwi-server's tree yet; until it is, copy the directory into kiwi-server's
`modules/` (or kiwi-modules', or the directory `KIWI_MODULES_HOME` names):

```sh
cp -r ~/.local/lib/kiwi-proxy/server-module/kiwi-proxy  ../kiwi-server/modules/
```

The machine pulls `ghcr.io/derlocke-ng/kiwi-proxy/gateway` (published by
`.github/workflows/images.yml`); nothing of kiwi-proxy is installed on it.

## A host

```yaml
hosts:
  sh3:
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

| Exit key | Meaning |
| --- | --- |
| `host` + `port` | the upstream SOCKS5. A name is resolved once, inside the gateway, before it seals |
| `via` + `port` | instead of `host`: another module of this stack (its address on the stack network), e.g. `tor` |
| `expose` | the host port its SOCKS5 is published on (required) |
| `username` / `password` | the upstream's credentials |
| `expose_user` / `expose_password` | what the host port demands |
| `ip` | the gateway's own address on the stack network (default: `.200`, `.201`, … from `ip_offset`) |

Module settings: `bind` (host address the exits are published on; default the
mesh address `vpn_ip`, `127.0.0.1` keeps them on the host), `open_firewall`
(default true: the exit ports are opened in the host firewall), `ip_offset`
(default 200), `image`.

## What it renders

One `kn-proxy-<name>` service per exit (quadlet or compose): `cap_drop: ALL` plus
`NET_ADMIN` and `NET_BIND_SERVICE`, `no-new-privileges`, a static address, the port
published on `bind`. Credentials are one root-owned 0600 file,
`<docker_dir>/kn-proxy/credentials`, mounted read-only; each gateway reads its own
row by `KF_EXIT_NAME`. No password is in a unit or in the environment. DNS is
remote (names go to the exit; use `socks5h`).

## Notes

- kiwi-server's `tor` module only accepts `socks_policy_accept` (default the mesh);
  add the stack subnet so a `via: tor` gateway is let in.
- Provider plugins (the kiwi-plugin-* modules) are a desktop/podman mechanism and do
  not run here; on a server the upstream is a remote SOCKS5 or a module of the
  stack (`tor`, a gluetun `vpn-client` SOCKS proxy).
- The exits are not passed through the master's reverse proxy or DNS; they are
  plain TCP on the host's mesh address.

Checked by `tests/unit/test_server_module.py`, which renders a host with
kiwi-server's own renderer when a kiwi-server checkout is beside this repository
(or `KIWI_SERVER_SRC` names one). Not yet run on a machine.
