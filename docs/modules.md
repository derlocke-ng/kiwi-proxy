# Provider modules

Most exits are a SOCKS5 proxy you were given. A **provider module** is for the
other case: it creates the upstream for you, through the Tor network, your own
VPN, 9proxy or Mysterium. This page explains how you install the modules and
make exits from them. How a module is built is on the page
[Writing a provider module](plugin-system.md).

## The modules

Each module is its own Kiwi app in its own repository.

| Module | Repository | Upstream | Account |
|---|---|---|---|
| `tor` | [kiwi-plugin-tor](https://github.com/derlocke-ng/kiwi-plugin-tor) | the Tor network | not needed |
| `vpn` | [kiwi-plugin-vpn](https://github.com/derlocke-ng/kiwi-plugin-vpn) | your WireGuard or OpenVPN config, through gluetun, with TCP and UDP | your VPN subscription |
| `9proxy` | [kiwi-plugin-9proxy](https://github.com/derlocke-ng/kiwi-plugin-9proxy) | 9proxy's residential IP addresses, ten exits per account | a 9proxy account |
| `mysterium` | [kiwi-plugin-myst](https://github.com/derlocke-ng/kiwi-plugin-myst) | the Mysterium dVPN, a decentralised VPN | a Mysterium identity |

A module that offers SOCKS5 (Tor, 9proxy, Mysterium) runs in its own
container on a private Podman network, `kf-providers`. The exit's gateway may
connect to exactly that container's address and nothing else. A VPN module
works the other way round: its container is a tunnel, and the gateway joins
the tunnel's namespace. The [VPN exits](#vpn-exits) section says what that
changes.

## Install a module

```bash
kiwi install kiwi-plugin-tor
kiwi-proxy module setup tor        # builds its image; kiwi-proxy setup does every module
kiwi-proxy module list
kiwi-proxy add tor-de --module tor --country de
kiwi-proxy up tor-de
```

kiwi-proxy starts a module's container when an exit needs it and stops it when
no running gateway uses it any more. When a module was updated, its image is
rebuilt the next time an exit on it starts.

## Settings a module needs

Some modules need something from you before they can run, such as Mysterium's
identity keystore and its passphrase, or a 9proxy login.

```bash
kiwi-proxy module settings mysterium
kiwi-proxy module config mysterium keystore=~/0x….json --ask passphrase
kiwi-proxy module config 9proxy username=YOU --ask password
```

`module settings NAME` lists what the module asks for. `--ask KEY` asks for a
value without showing what you type. `module status` and `module list` say
when a module is not configured yet. In the app, the same settings are under
**Provider modules → Configure…**.

## Choose where an exit leaves

```bash
kiwi-proxy module countries tor
kiwi-proxy module leases mysterium --country DE --kind residential
kiwi-proxy add de-1 --module mysterium --country de --lease 0x…
```

A **lease** is one exit that a module can offer: a Mysterium node, a 9proxy
port, a VPN server. `module leases NAME` lists them, best first.
`--country`, `--kind` (the IP type: residential, hosting, cellular …) and
`--search` (any part of an id, a city or an ISP) narrow the list. `--lease ID`
on `add` picks one. `module countries NAME` lists the countries a module can
exit in, with counts where the module knows them.

## Tor exits

```bash
kiwi-proxy add tor-nordic --module tor --country de,se,ch --never hu,tr
kiwi-proxy module nodes tor --country se
kiwi-proxy set tor-nordic --node FINGERPRINT
kiwi-proxy nyx tor-nordic
```

- `--country` takes a list of countries the exit may leave through, and
  `--never` a list of countries it never leaves through.
- `--node FINGERPRINT` restricts the exit to one relay, and can be repeated.
  `module nodes tor` lists the running exit relays, fastest first.
- `kiwi-proxy prefs --tor-never five|nine|fourteen|none` keeps every Tor exit
  out of the Five, Nine or Fourteen Eyes countries. With
  `--tor-never-all on`, no relay of a circuit is in those countries, not only
  the exit relay. This leaves fewer relays to choose from.
- `kiwi-proxy nyx EXIT` opens nyx, Tor's own monitor, for a Tor exit that is
  up.

Each exit gets its own Tor circuit. For this, kiwi-proxy gives every Tor exit
its own SOCKS username and password, and Tor keeps separate circuits for
separate credentials (`IsolateSOCKSAuth`).

### Tor Browser

Tor Browser sends its own SOCKS username and password for every site, so that
each site gets its own circuit. A Tor exit therefore uses
`--socks-auth passthrough` by default: the gateway puts the exit's own
username in front of Tor Browser's, so the sites keep their own circuits and
the exits stay apart. A member that sends no credentials still gets the exit's
own, so the same exit serves Tor Browser, another browser and a tool alike.

A Tor exit in passthrough mode also gets its own Tor with a control port, for
Tor Browser's New Identity, its circuit display and onion-site client keys.
The gateway lets Tor Browser reach that control port only through a filter:
commands that read status pass, commands that would change Tor's configuration
are refused. The control port's password is stored like the exit's other
passwords.

## VPN exits

```bash
kiwi-proxy add home --module vpn --config ~/wg0.conf --expose 1081
kiwi-proxy module sources vpn
kiwi-proxy add office --module vpn --from "Office VPN"
```

- `--config FILE` takes a WireGuard `.conf` or an OpenVPN `.ovpn` file. The
  module accepts only a full tunnel, a config that sends all traffic through
  the VPN. The whole file, keys included, is stored as the exit's secret and
  deleted with the exit.
- `--from NAME` takes a connection that NetworkManager already has.
  `kiwi-proxy module sources vpn` lists them. In the app, it is **Import…**
  beside **Choose…**.
- A config that asks for a username and password needs `--login USER`. You are
  asked for the password, or `--login-password-stdin` reads it.

Each VPN exit runs its own gluetun container, and that container creates the
exit's network namespace. Its firewall is the kill switch, the rule that blocks
all traffic when the tunnel is down. Its only route is the tunnel. The gateway
joins this namespace, so members of a VPN exit send TCP and UDP through the
VPN, and nothing leaves when the tunnel is down.

When the VPN server stops answering, the tunnel reconnects by itself, in the
same namespace: members keep their place, and nothing leaves meanwhile. On the
test machine, after the server had been unreachable for three minutes,
WireGuard was back 2 seconds and OpenVPN 14 seconds after it answered again.
Meanwhile the exit says **VPN not answering**: its row and details in the app,
`kiwi-proxy show`, and the rows of kiwi-fox profiles and kiwi-custodia boxes on
it. kiwi-proxy asks the tunnel itself, with a TLS handshake to 1.1.1.1 or
9.9.9.9 from inside the namespace, about every 15 seconds while a window is
open. Only when the tunnel's container itself ends is the exit taken down, never
left open; the next `up` starts a new tunnel.

A WireGuard config's `MTU` suits the network it was made on. Before the tunnel
starts, the module measures the path to the server. If the config's MTU plus
WireGuard's 60 bytes (80 over IPv6) does not fit, the tunnel uses the largest
MTU that does; the exit's details and `kiwi-proxy show` say so ("MTU 1316,
fitted to the path (config 1352)"), and the stored config stays as it is. A
config without an `MTU` line is left to gluetun, which measures the path
itself.

A VPN exit always resolves names in its gateway; `--dns remote` is refused. A
host port (`--expose`) works on a VPN exit too, and changing it starts the
tunnel again.

The vpn module refuses to start an exit while another exit with the same
WireGuard key is up, because one key works in one place at a time. You can
have as many VPN exits as you like, each with its own tunnel.

## 9proxy exits

```bash
kiwi-proxy module config 9proxy username=YOU --ask password
kiwi-proxy add us-1 --module 9proxy --country us
kiwi-proxy renew us-1
```

One 9proxy daemon serves ten ports, 60000 to 60009, and each new 9proxy exit
gets the next free one. An eleventh exit is refused. An exit starts on an IP
address from 9proxy's list for today, without using up a new one.
`kiwi-proxy renew EXIT`, or **New IP** in the exit's details, asks for a new
address. This uses one IP address from your 9proxy balance, and the app asks
first.

## Commands

| Command | What it does |
|---|---|
| `module list` | Lists the installed modules (`--json`). |
| `module status NAME` | Shows whether the module's image is there, whether it runs, and whether it is configured. |
| `module settings NAME` | Lists what the module needs from you. |
| `module config NAME KEY=VALUE … [--ask KEY]` | Gives the module its settings. |
| `module sources NAME` | Lists configs the module finds on this computer (vpn: NetworkManager connections). |
| `module countries NAME` | Lists where the module can exit, with counts where it knows them. |
| `module leases NAME` | Lists the module's leases (`--country`, `--kind`, `--search`). |
| `module nodes NAME` | Lists the relays the module can exit through, fastest first (Tor; `--country`, `--search`, `--limit`, default 40). |
| `module up NAME`, `module down NAME` | Starts or stops a module's container by hand (`--lease`, `--country`). |
| `module logs NAME` | Shows the recent log of the module's running containers. |
| `module setup NAME` | Builds or pulls the module's image. |
| `module doctor` | Checks every installed module. |
