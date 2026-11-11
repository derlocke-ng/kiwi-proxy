# Changelog

## 0.15.0

- **A VPN exit from a connection NetworkManager already has.** `kiwi-proxy add
  NAME --module vpn --from "My VPN"`, `kiwi-proxy module sources vpn` to list
  them, and Import… beside Choose… in the exit dialog. Needs kiwi-plugin-vpn
  0.5.0. Checked on the VM: the list, an OpenVPN connection carrying traffic, a
  WireGuard one matching its keyfile, an expired one refused with its date.
- Module hooks `config_sources` and `config_from`, for any module that finds
  configs on the machine.

## 0.14.0

**Several DNS services per exit; the fastest that answers.** An exit's resolver
asked one DNS-over-HTTPS service; when that one did not answer at its start, the
exit had no names for a while. Now an exit asks any of Quad9, Mullvad, Cloudflare
and Google you choose, and dnscrypt-proxy uses the fastest of them that answers
(`lb_strategy = 'first'`); one that is down costs nothing.

- New exits ask all four (Preferences → DNS services). A service chosen there
  before stays the choice; existing exits keep theirs until you edit them.
- The exit dialog: Resolve names through (a resolver in the gateway, or the exit
  itself) and a switch per service. `--upstream quad9,mullvad` on `add`, `set`
  and `prefs`.
- `DnsConfig.upstreams` (the list) and `.services`; `upstream` stays the first,
  for older readers.

## 0.13.0

- **A host SOCKS5 port on a VPN exit.** `--expose` (Offer a SOCKS5 port in the
  app) works on VPN exits too: the port is published on the exit's tunnel, whose
  namespace the gateway shares, and changing it starts the tunnel again. Checked
  on the VM: the VM's own requests through the port leave as the VPN's IP.
  Needs kiwi-plugin-vpn 0.4.0.
- **VPN exits are labelled by their server** (`vpn:94.16.108.143:51820`), not by
  an address on the providers bridge.
- An exit's line says only what its label does not: no VPN exit's own id, no
  9proxy port twice, and the country in capitals (`9proxy:…:60001 (DE)`).

## 0.12.0

**9proxy: one daemon, ten exits, a new IP only when you ask.** Needs
kiwi-plugin-9proxy 0.3.0.

- **A module's container can serve several leases.** `providers.container_of`
  asks the module which container serves a lease (9proxy: one daemon for its ten
  ports) and `providers.lease_alive` whether a lease is served (a port still
  bound to an IP). The gateway's health, repair and logs use them.
- **Leases handed out.** A module with `assign_lease` gives each new exit the
  next free one (9proxy: a port, 60000-60009), and an eleventh is refused.
- **New IP.** `kiwi-proxy renew EXIT`, and New IP in the exit's details, for a
  module that sells IPs (`renew`). The app asks first and says it uses one IP
  from the balance; the exit is measured again when it is up.
- Checked on the VM: Kiwi Fox (Camoufox) on a 0.11 VPN exit loads pages through
  the VPN.

## 0.11.0

**VPN exits: TCP and UDP through your own WireGuard or OpenVPN config.** Needs
kiwi-plugin-vpn 0.3.0. Checked on the VM with real configs (WireGuard, and OpenVPN
over TCP): two VPN exits at once, a Kiwi Custodia box sending TCP and UDP through
its VPN, and nothing getting out with the tunnel down.

- **Tunnel exits.** A module whose manifest says `joins="tunnel"` (a VPN: gluetun,
  one per exit) owns the exit's network namespace: its firewall is the kill switch
  and its route the tunnel. The gateway joins it instead of building its own, its
  forwarder connects targets directly (`KF_UPSTREAM=direct`), and kiwi's DNS and
  blocklists ride the tunnel. `gateway.is_tunnel(exit)` says which exits these are.
  If the tunnel's container ends, the exit is taken down (`heal`) or started over
  (`up`): fail closed.
- **One config per exit.** `kiwi-proxy add NAME --module vpn --config FILE`, and
  New exit → Config: Choose… in the app. The module checks the file (a full
  tunnel, for the internet); it is kept whole as the exit's secret (kind
  `vpnconfig`) and forgotten with the exit.
- A VPN exit resolves names in its gateway and has no host SOCKS5 port yet.
- **Every resolver exit starts sooner.** The gateway's "resolver up" check now asks
  127.0.0.2 itself. It asked the container's own resolver, which the firewall
  blocks, so it waited out its 20 s and a first measurement could find no DNS yet.

## 0.10.1

**Tor Browser's circuit display works.** The gateway puts the exit's token in
front of Tor Browser's per-site SOCKS username, so Tor's events named a username
Tor Browser did not know and the circuit display stayed empty. The control filter
now hands Tor Browser its own username back (long ones folded to a hash too).
Checked on the VM with the real Tor Browser 16.0: the circuit shows three relays
with countries; New circuit for this site and New Identity each change the exit.

- The gateway log notes each New Identity and every command the control filter
  refuses (the command word; for GETINFO/GETCONF the keys, nothing else).

## 0.10.0

**Tor Browser's control port, filtered.** New Identity, the circuit display and
onion-site client keys need Tor's control port; Tor Browser had none (it ran
proxy-only). Needs kiwi-plugin-tor 0.5.0; Kiwi Fox 0.10.3 uses it.

- A Tor exit for Tor Browser (passthrough) gets a Tor of its own with a
  password-protected control port on the providers bridge; the password is the
  exit's, kept like its other secrets.
- The gateway's forwarder filters it on 127.0.0.1:9151 in the exit's namespace,
  the way Whonix's onion-grater does: New Identity (SIGNAL NEWNYM), status and
  circuit reads, the events Tor Browser listens to, and onion-site client keys go
  through; what would change Tor is refused (510) or answered "250 OK" without
  reaching it (taking ownership, DisableNetwork=0); the password and Tor's
  configuration stay out of reach. The gateway's firewall permits that one port.
- **The gateway image is rebuilt when kiwi-proxy is newer** than the image, at the
  next start, as module images are since 0.9.2; a failed rebuild stops the start.

## 0.9.3

- **The Eyes group for every relay, if you want it:** Preferences → Tor → "Also as
  entry and middle relays" (`kiwi-proxy prefs --tor-never-all on`). Off, the group's
  countries are never the exit (as before); on, never any relay of a circuit. The
  (?) says what it costs: fewer guards to choose from.
- **Tor's monitor, nyx,** for a Tor exit that is up: "Tor monitor (nyx)" in its
  menu opens it in a terminal, `kiwi-proxy nyx EXIT` in this one. Needs
  kiwi-plugin-tor 0.4.1.

## 0.9.2

- **A module's image is rebuilt when the module is newer.** Updating a module
  left its image as it was until `kiwi-proxy module setup` ran, so a Tor image
  from before kiwi-plugin-tor 0.4 would have ignored an exit's Only and Never
  lists and exited anywhere. Images now carry a hash of what they are built from;
  the first start after an update rebuilds a stale one (about 30 seconds for Tor,
  once), and a rebuild that fails stops the start instead of using the old image.

## 0.9.1

- **0.9.0 shipped without two files** (the "?" help and the DNS page) and with
  three others as they were in 0.8.2, so its window and `kiwi-proxy prefs` failed
  to start. 0.9.1 is 0.9.0 as it was meant to be. Update if you have 0.9.0.

## 0.9.0

**Where a Tor exit may leave.** Needs kiwi-plugin-tor 0.4.0 for the lists; with an
older Tor module an exit keeps its one country.

- **Only and Never, per exit.** The exit editor's "Exits through" opens the
  exit's own country list (Only and Never on every row, never both) and its relay
  list (the running exit relays from the Tor Project's directory, fastest first,
  searchable by name, network or fingerprint). A country set to Never takes its
  relays out of the list at once, and the line at the bottom says what Tor will
  do. On the command line: `--country de,se,ch --never hu,tr --node FINGERPRINT`,
  and `kiwi-proxy module nodes tor` lists the relays.
- **Preferences → Tor:** one choice of four, no group or the Five, Nine or
  Fourteen Eyes, blocked for every Tor exit; their countries are not offered in
  the lists at all. Each choice says how many exits it leaves.
  `kiwi-proxy prefs --tor-never nine`.
- **Each selection runs its own Tor.** Two Tor exits with different countries
  shared one Tor process before, and with it the first one's country. A Tor
  container is now keyed by what its exits ask for.
- An exit made with `--country` before keeps that one country; an exit without
  lists is written exactly as before, so an older kiwi-proxy still reads it.
- `kiwi-proxy prefs` shows and sets what new exits start with and the Eyes group.

## 0.8.3

- **Preferences → DNS:** what a new exit starts with, its resolver and whether it
  blocks ads and trackers; each exit is still changed in its own editor. Used by the
  app, `kiwi-proxy add` and exits other apps make.
- **Short texts, the rest behind a (?).** Rows and groups say what they are in a
  few words; a small (?) opens the explanation and a link to the app's page on
  kiwi-network.eu. The helper is shared with Kiwi Fox and Kiwi Custodia.
- The list of exits is wider (up to 920 px), like the other two apps.

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
