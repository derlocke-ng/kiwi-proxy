# Changelog

## 0.8.2

- **A dead proxy fails at once.** Bringing up an exit whose proxy did not answer
  took 37 to 52 seconds (measured on the dev VM): 15 for the pre-flight's connect,
  about 21 for the gateway's resolver waiting on an upstream that never answers,
  and 5 for each of three echo services. Before a gateway is started its proxy is
  now asked for a SOCKS5 greeting: a refused port fails in under a second, no
  answer in five, and the error says which ("refuses connections", "does not
  answer", "is not a SOCKS5 proxy"). Provider exits (Tor, Mysterium) are not
  affected.
- **Check and repair** in the menu, and `kiwi-proxy storage check|repair`:
  podman's quick storage check (`podman system check --quick`, 0.07 s; the full
  one takes 13 s and reported 1142 mtime-only changes on healthy images), with
  every broken container named and whose it is. Repair removes Kiwi's broken
  containers, others only when asked (`--theirs-too`), then lets podman repair
  what is left. The dialog is shared with Kiwi Fox and Kiwi Custodia.
- **Repair on start:** the window removes kiwi-proxy's own containers a crash or
  a reset left ("created", "exited", "dead"); `kiwi-proxy storage leftovers
  --remove` by hand. One made in the last two minutes is left alone, since
  another app may be starting it.

## 0.8.1

- **Snapshot everything now, in the app.** `kiwi-proxy snapshot now` had no
  counterpart in the window: there was only Snapshots… per exit. The main menu has
  "Snapshot everything now", and the Snapshots preferences page a row with the same
  button; both take every exit and every module's settings and say what they took.
  The page's row is shared, so Kiwi Fox and Kiwi Custodia offer the same for theirs.

## 0.8.0

**Snapshots: your exits on your other devices.** One folder, chosen once per
device, holds encrypted snapshots; your sync client (Nextcloud) carries it to your
other devices, and Kiwi Fox and Kiwi Custodia will use the same folder.

- **What travels:** each exit with both of its passwords, and each provider
  module's settings with its podman secrets (for Mysterium the keystore, the
  identity and its passphrase; the node's database stays).
- **When:** automatically after you add or change an exit or configure a module,
  and whenever you ask. Five are kept per item, ten at most.
- **Encrypted** with gpg (AES-256, the passphrase stretched to gpg's maximum).
  The passphrase is entered once per device and kept in its GNOME keyring. Nothing
  in the folder names what it holds: no exit names, no device names, no times.
  A snapshot opens by hand with gpg, zstd and tar.
- **Which copy is newer** is decided by lineage, not clocks. An exit the folder
  holds a newer copy of says so in its row, and bringing it up asks first: restore
  and bring up, or bring up as it is. When both devices changed it, you choose.
  A restore keeps what was here as a snapshot first, so it can be undone.
- **In the app:** Preferences (Ctrl+,) with the Snapshots page; Snapshots… in an
  exit's menu (history, Snapshot now, Restore); a group "In your snapshot folder,
  not on this device"; a banner when snapshots are locked; "Use a snapshot folder"
  on a device with no exits yet.
- **On the command line:** `kiwi-proxy snapshot setup | status | unlock | lock | set
  | list | now | history | restore | forget`. `up` warns when the folder holds a
  newer copy. See docs/snapshots.md.
- Provider modules may name what a snapshot leaves out (`snapshot_exclude`).
- Snapshots need `gpg` and `zstd`; everything else works without them.

## 0.7.3

- **A bigger window, and the size you leave it at.** The window opened at
  760×620, smaller than its own dialogs (the node picker is 720×780), so those
  came up squeezed. It now opens at 1040×840, and the size and maximized state
  it has when closed are kept in `config/window.json` for the next start.

## 0.7.2

- **The picker shows the id you clicked.** Choosing a module's exit — a Mysterium
  node — showed short ids in the list and offered a field "Or an id to force"
  that had nothing to do with the list. Clicking a row now puts its full id into
  that field, where it can be read and copied (a copy button sits beside it);
  typing there forces an id the list does not show, as before. The field says
  what it wants, by example: "Node id, 0xcbb6…eb78 for example".
- **Modules name their leases.** A provider may set `lease_noun` ("node",
  "server", "port"); the picker, the editor's row (titled *Node* instead of
  *Exit*, with the full id and a copy button), the details dialog ("mysterium ·
  node 0x… · country de", copyable) and `module leases` use it. A module that
  does not say still has "exits".
- The modules dialog offers to copy a configured identity (0x…) when the module
  reports one.

## 0.7.1

- **A member that must keep its contents is kept.** Taking an exit down — the
  stop button in Kiwi Proxy, `kiwi-proxy down`, a replace, `reap` — removes every
  container joined to its gateway, and a Kiwi Custodia box is one: whatever was
  installed in it went with the exit. A member now labels itself
  `kiwi-proxy.snapshot=<image>` and kiwi-proxy commits it to that image before
  removing it; when the commit fails the member is left in place. `kiwi-proxy
  down` and the confirmation in Kiwi Proxy say which members are kept.
- **A failed `podman ps` is not "nobody is inside".** `reap` and `release` tear a
  gateway down when no running member is left, and a listing that failed (podman
  under load times out) looked like that. It is an error now — in the window too,
  which used to take the exit down unasked when it could not list the members.

## 0.7.0

- **An exit is IPv4 to the world.** A CONNECT by name used to be handed to the
  upstream to resolve, and a SOCKS upstream with IPv6 (Mullvad's) picked an AAAA
  record now and then — so `kiwi-proxy check`, a `curl` through the host port and
  the probes showed the exit's IPv6, while a member that resolved through the
  gateway's resolver (which answers no AAAA) connected by IPv4. Two addresses for
  one exit is a tell. In resolver mode the forwarder now resolves names itself,
  through that resolver, and connects the upstream by IPv4; a name with no A
  record is refused (host unreachable). Remote-DNS exits (Tor) pass names through
  as before. The pre-flight measurement from this machine (`up`, `test`) asks by
  IPv4 as well, so the exit it reports is the one members get. `kiwi-proxy setup`
  rebuilds the gateway image.

## 0.6.1

- **Check the exit works on an exit that is down**: the gateway is brought up for
  the measurement and taken down again (`kiwi-proxy check NAME` too), so an exit
  need not be running to learn where it leaves. kiwi-fox shows that record.
- **A provider that died is started again behind its gateway.** A tunnel node
  whose session ended fails closed and exits (kiwi-plugin-myst 0.5.1);
  `gateway.heal()` — run by the app's poll and by `kiwi-proxy reap` — starts a
  fresh node and adapter on the same pinned address, and the gateway, its members
  and their route stay. Tunnel containers get no podman restart policy any more:
  a restarted tunnel lost its adapter to the old namespace and answered nothing.
- A module exit whose provider container has gone says so in its row ("provider
  gone — see its logs") and from `check`, instead of a bare SOCKS code; and the
  probe's SOCKS refusals are spelled out ("network unreachable at the exit — a
  tunnel exit whose tunnel is down fails closed").

## 0.6.0

Seeing and choosing a module's exit, and resolving names, made plainer.

- **Container logs.** The exit details has a **View logs** button, and the CLI
  `kiwi-proxy logs NAME` (and `module logs NAME`), showing the provider's own log
  — did Mysterium connect, what error is it stuck on — and the gateway's, for any
  module (tor, vpn, 9proxy, mysterium). A module that declares its `log_marker`
  gets its own lines quoted in a start-up error, not the daemon's debug noise.
- **One "Resolve through" choice** replaces the DNS mode plus a separate upstream:
  the exit itself (.onion, the exit's own resolver), or a named resolver run in the
  gateway — Quad9, Cloudflare, Mullvad, Google. Ad-blocking applies either way, as
  before.
- **The country field can be searched** (it is a real search-as-you-type list now),
  and the provider picker copies the selected id and resolves a typed short id
  (`0xcbb6…eb78`), prefix or any unique piece to the full one, so an exit is easy to
  pin or change by id.
- **One module sets up at a time** — two image builds at once made podman serialise
  and look hung — and a build says plainly when the module still needs configuring
  (Mysterium with no identity yet).

## 0.5.0

Choosing a module's exit the way Mysterium's own app does.

- **A picker for a module's exit.** The exit editor's Exit row opens a dialog
  that lists every exit the module offers for the country — a Mysterium provider,
  a gluetun server — best first, with short ids ("0xcbb6…eb78"), place, IP type,
  quality and ISP; a search box that takes any part of an id, a city or an ISP;
  one toggle per IP type (residential, hosting, cellular, …); and a field to
  force an id the list does not show. The exit of an existing module exit is
  changed the same way (`kiwi-proxy set NAME --lease ID` on the CLI; `up
  --replace` applies it to a running gateway).
- A lease carries `kind` (the IP type), `quality` and `isp` where the module
  knows them, and `module leases NAME --country DE --kind residential --search
  cbb6` filters like the picker. kiwi-plugin-myst 0.4.0 fills them in and
  offers every provider instead of the best sixty — which were all hosting.

## 0.4.0

What a module needs from you, asked in one place.

- **Module settings.** A module declares what it needs before it can run —
  a file, a password, a text — and the app's Provider modules dialog gets a
  **Configure…** button for it: a file chooser, an unechoed password field.
  The CLI has `module settings NAME` and `module config NAME KEY=VALUE …
  --ask KEY`; `module status` and `module list` say when a module is not
  configured. (kiwi-plugin-myst 0.3.0 uses it for the identity keystore and
  its passphrase.)
- **Every country, by name.** The exit editor's country field is a searchable
  list — "DE — Germany (361)" — filled by the module with where it can actually
  exit and how many exits it has there (kiwi-plugin-tor 0.3.0: Tor's running
  exit relays from the Tor directory; kiwi-plugin-myst 0.3.0: discovery's
  provider counts). A module that cannot say gets every country there is.
  `kiwi-proxy module countries NAME` prints the same list.
- **Leases by country.** `module leases NAME --country DE`, and the exit editor
  asks the module again as the country changes — Mysterium has hundreds of
  providers per country. Modules that cannot filter are called as before.
- The editor loads a module's leases off the main thread, and keeps the choice
  made so far while it does.
- **Tunnel modules work under SELinux.** A container given `/dev/net/tun` runs
  with `--security-opt label=disable`: Fedora's `container_t` may not open the
  device, so every tunnel (gluetun, the Mysterium node) failed with "failed to
  create TUN device: permission denied". Caps, `no-new-privileges` and the user
  namespace are unchanged.
- A provider container that fails to start is removed again, and the error
  quotes its last log lines — stdout and stderr, colours stripped. `kiwi-proxy
  down` of an exit whose gateway never came up still lets its provider go.
- Measuring an exit asks ipinfo.io and then am.i.mullvad.net when ifconfig.co
  refuses (a hosting exit gets an empty 429 there), and a refusal is reported
  with its HTTP status instead of "unparseable data ''".
- `--country` takes only a real two-letter code, lowercased; a word is refused
  with a pointer to `module countries`.

## 0.3.1

The app has its icon back, and is called Kiwi Proxy.

- **GNOME could not match the window to its entry.** The window's app-id was
  `dev.kiwinetwork.KiwiProxy` while the desktop entry was `kiwi-proxy.desktop`
  with `StartupWMClass=kiwi-proxy`, so the shell showed a blank icon and no name.
  The id is `eu.kiwinetwork.KiwiProxy` now, like the other kiwi apps, and the
  entry and the icon are named after it; the install writes the launcher's
  absolute path into `Exec`, and removes the old file names.
- The app is **Kiwi Proxy** in the grid, the window title and About — the command
  keeps its dash, the app does not.
- `show`, the app's details and the editor no longer say ad-blocking is off in
  remote DNS mode: since 0.3.0 the lists apply in both modes, and the editor
  offers them in both; only the resolver's upstream is resolver-only.

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
