# Changelog

## 0.3.0

Exits are the proxies other apps share.

- **Ad-blocking in remote DNS mode too.** The forwarder gets the exit's blocklist
  whatever the DNS mode, so a browser in remote mode — Tor Browser, anything
  that hands the proxy its names — has listed names refused as well. Only the
  resolver and its config stay out of a remote exit; `--no-blocklist` still
  turns filtering off. A running remote exit picks this up when it is next
  brought up.
- **Tor exits are passthrough by default.** An exit on an isolation provider
  (the tor module) is created with `socks_auth=passthrough`: a member without
  SOCKS credentials still gets the exit's token, Tor Browser keeps a circuit
  per site, so one exit serves every kind of member and nothing has to be
  switched later. `--socks-auth inject` keeps the old behaviour; existing
  exits are left as they are.
- Docs: a consumer — kiwi-fox 0.4, kiwi-pentesting, kiwi-custodia — references
  an exit the user defined; several profiles or tools share the exit's one
  gateway and each lets go with `release(ignore=…)`. `docs/consumers.md` says
  how, and no longer tells a consumer to register an exit per profile.

## 0.2.1

No gateway could start. Fixed.

- **The forwarder crashed at start in every gateway without a host listener**,
  which is every kiwi-fox profile and every plain `kiwi-proxy up`. With
  `KF_EXPOSE_CREDS_FILE` unset it read the empty path as the current directory
  and died with `IsADirectoryError` before listening; the gateway then exited
  and every bring-up failed with "gateway exited during start". An empty path
  now means no credentials. Two tests start the forwarder exactly as a gateway
  does, with and without the host listener; the one test of its entry point had
  only ever set the listener up.

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
