# Architecture

## Exits and gateways

An **exit** (`models.Exit`, stored by `exits.py`) is a named upstream: an endpoint —
a remote SOCKS5, or a provider module plus a lease/country — its DNS mode, whether
its SOCKS5 is published on the host, and how the forwarder treats client
credentials. It is data; nothing runs.

A **gateway** (`gateway.py`) is an exit brought up: one container,
`kf-gw-<exit id[:12]>`, that owns a network namespace.

```
                         ┌─────────────────────────── gateway netns ───────────────────────────┐
 members                 │ nftables output: default drop                                       │
 (--network container:)  │   ct established · lo · <one permitted address>:<port>              │
   kiwi-fox browser  ───►│ forwarder 127.0.0.1:1080 ──── adds the exit's credentials ─────────►│──► upstream SOCKS5
   pentest tool      ───►│ dnscrypt-proxy 127.0.0.2:53 ─ DoH, through the forwarder            │    (remote, or a
                         │ host listener 0.0.0.0:1081 ── only when exposed; may want a password │     provider on
 host apps ── publish ──►│ nftables input: lo, established, and tcp/1081 when exposed           │     kf-providers)
                         └──────────────────────────────────────────────────────────────────────┘
```

Every byte a member or a host client sends leaves through the one permitted
destination. A member has no routing table of its own; the host listener is the
same forwarder on another port. UDP leaves nowhere: no QUIC, no WebRTC media, no
plaintext DNS.

## Bringing one up

`gateway.up(exit)`:

1. **plan** — a module-backed exit brings its provider up on the `kf-providers`
   bridge (idempotent) and permits that container's static address; a plain exit is
   resolved on the host to a literal address and measured from the host.
2. **reuse** — if the gateway already runs with the same settings (a hash of its
   rendered spec and resolver config, in the `kiwi-proxy.config` label) it is handed
   back as is. That is how a browser and a pentest tool share one identity.
3. **replace** — running with other settings: replaced only when nobody uses it or
   the caller says `replace=True`; whoever joined is removed first, because podman
   cannot swap a namespace out from under its members.
4. **start** — credentials as podman secrets, the container, then wait for
   `ready — the namespace is sealed`.
5. **measure** — a provider exit the host cannot reach is measured from inside,
   through the forwarder (`kf-exitinfo`).

## DNS and ad-blocking

An exit's `dns.mode` is `resolver` (the default) or `remote`.

- **resolver** — dnscrypt-proxy at 127.0.0.2 inside the gateway, DoH upstream
  through the forwarder, `blocked_names_file` = the exit's merged blocklist. The
  same list is handed to the forwarder (`KF_BLOCKLIST`), which refuses a CONNECT by
  name to a listed domain or a name under it (`REP_NOT_ALLOWED`) — that covers
  clients that never ask the resolver: `socks5h` on the host port.
- **remote** — no resolver, no list: every name goes to the exit as is. Tor
  Browser's exits are remote.

Each set of lists has its own merged file in `blocklists/` (`blocked-names.txt` for
the default oisd big, `blocked-names-<lists>.txt` otherwise), replaced atomically
by `kiwi-proxy dns update`, which refreshes every list any exit uses. The directory
is mounted, not the file, so a running gateway sees the new one; the forwarder
re-reads it when its mtime changes. A kiwi-server gateway has no host-side lists:
`KF_BLOCKLIST_URLS` makes it fetch them through its own exit (`kf-exitinfo --out`).

## Who keeps it up

- `release(exit_id, ignore=…)` — a consumer is done. The gateway goes unless another
  running member is still inside it or it is held.
- `hold` — `kiwi-proxy up` marks an exit held: it stays until `kiwi-proxy down`.
- `down(exit_id)` — always: members, gateway, secrets, and the provider once no
  other gateway exits through it.
- `reap()` — exited gateways, and running ones nobody uses (no running member, not
  held, not exposed); then `reconcile()`.
- `reconcile()` — a gateway whose pinned provider address no longer matches the
  provider's is torn down: fail closed rather than forward to whatever holds it now.

## Labels

Every container kiwi-proxy starts carries `kiwi-proxy.role`
(`gateway|provider|tunnel|adapter`); that is the one filter. Gateways also carry
`kiwi-proxy.exit`, `kiwi-proxy.module`/`kiwi-proxy.lease` (provider exits),
`kiwi-proxy.expose` and `kiwi-proxy.config`. `app` is the consumer's: kiwi-fox sets
`app=kiwi-fox` plus its own `kiwi-fox.role=gateway` and `kiwi-fox.profile=<id>`, so
tools that discover kiwi-fox gateways by label keep finding them.

## Names

Podman object names keep the `kf-` prefix from kiwi-fox: `kf-gw-…`, `kf-prov-…`,
`kf-creds-…`, `kf-expose-…`, the `kf-providers` bridge on `10.89.231.0/24`. A
rootless podman will not create a second network on a subnet in use, so the bridge
cannot be renamed without stranding hosts that ran kiwi-fox before the split.
Images are `kiwi-proxy/gateway:latest` and `kiwi-proxy/<module>:latest`.

## On disk

```
~/.local/share/kiwi-proxy/
  exits/<id>/exit.json       an exit (no passwords)
  modules/<name>/            installed provider modules
  modules-state/<name>/      their writable state (VPN config, identities)
  blocklists/                resolver stamps, blocklists, the merged list
  providers.json             measured provider exits
$XDG_RUNTIME_DIR/kiwi-proxy/
  exits/<id>/                generated resolver config and resolv.conf for members
  holds/<id>                 exits kept up with `kiwi-proxy up`
~/.config/kiwi-proxy/secrets/  passwords, only on a machine without a Secret Service
```
