# Changelog

## 0.2.0

- **Ad-blocking everywhere a name is seen**: the forwarder refuses blocked names
  for socks5h clients on the host port, not only the in-gateway resolver; each set
  of lists gets its own merged file (one shared file let exits overwrite each
  other's lists); `dns update` refreshes every list an exit uses; kiwi-server
  gateways fetch their lists through their own exit (`adblock`, `blocklist_urls`);
  `--no-blocklist`.
- **The app** (`kiwi-proxy-gui`, GTK 4 + libadwaita): exits with their state, bring
  up/take down, add/edit (endpoint or provider module, host port and password, DNS,
  Tor Browser passthrough), details with the gateway's members, copy the host
  proxy address, provider modules and their images, setup. Choose blocklists per
  exit, test an upstream before saving, duplicate an exit.
- Ships its own icon from kiwi-icons (`svg/classic/kiwi-proxy.svg`).

## 0.1.0

The proxy engine kiwi-fox carried, split out into its own app.

- **From kiwi-fox, unchanged in behaviour**: the gateway image (nftables
  default-drop with one permitted destination, the credential forwarder including
  Tor Browser passthrough, dnscrypt-proxy through the exit), endpoint parsing and
  pre-flight, DNS stamps and blocklists, the provider plugin contract and loader,
  the `kf-providers` bridge with static provider addresses, reconcile.
- **Exits**: named upstreams any app can create (`kiwi-proxy add/list/show/set/rm`),
  passwords in the Secret Service or 0600 files.
- **Headless gateways**: `kiwi-proxy up` brings an exit up with no browser and keeps
  it up; `down`, `name`, `check`, `ps`, `reap`. A gateway is shared: a second
  consumer gets the running one, and it goes when its last member leaves.
- **Host listener**: `--expose [ADDR:]PORT` publishes an exit's SOCKS5 on the host,
  optionally password-protected; `kiwi-proxy@NAME.service` keeps one up at login.
- **kiwi-server module** (`server-module/kiwi-proxy`): exits for the mesh on a node
  or the master; the gateway image is published to GHCR for it.
- Consumer API for kiwi-fox and kiwi-pentesting (`docs/consumers.md`).
