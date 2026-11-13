# Using kiwi-proxy

This page explains how you add exits, bring them up, use them from the host and
from containers, and keep them tidy. It lists every command of `kiwi-proxy`.
Exits from Tor, a VPN, 9proxy or Mysterium are on the
[provider modules](modules.md) page, and how names are resolved is on the
[DNS and ad-blocking](dns.md) page.

## Exits and gateways

An **exit** is one upstream connection, saved under a name. The upstream is the
proxy your traffic is sent to: a SOCKS5 proxy you were given, or one that a
provider module creates for you. An exit by itself is only a saved entry, and
nothing runs for it.

When you bring an exit up, kiwi-proxy starts its **gateway**, a container named
`kf-gw-` followed by the first 12 characters of the exit's id. The gateway
creates a network namespace whose firewall drops everything except the
connection to the exit's upstream. Inside it runs a SOCKS5 forwarder on
`127.0.0.1:1080`, which adds the upstream's username and password. In the
default DNS mode a DNS resolver runs there as well, on `127.0.0.2:53`. A
container that joins the namespace is a **member** of the
gateway. It has no route of its own, so when the gateway stops, the member has
no connection at all.

UDP is not forwarded, so QUIC, WebRTC media and plain DNS do not leave the
gateway. The one exception is a [VPN exit](modules.md#vpn-exits), which carries
TCP and UDP through its tunnel.

## Add an exit

```bash
kiwi-proxy add work socks5://user:pass@proxy.example.net:1080
kiwi-proxy add backup proxy.example.net:1080:user:pass
kiwi-proxy list
```

An endpoint is the address of the upstream. You can write it in these forms:

| Form | Example |
|---|---|
| A URL | `socks5://user:pass@host:port`, also `socks5h://…` |
| The format many proxy vendors use | `host:port` or `host:port:user:pass` |

`http://…` and `https://…` URLs are accepted as well, but only their host,
port, user and password are read. The upstream must still be a SOCKS5 proxy:
kiwi-proxy does not speak HTTP to it.

The password never goes into the exit's file. kiwi-proxy stores it in your
desktop keyring through `secret-tool`. On a machine without a keyring, for
example a server you reach over SSH, it stores it in a file under
`~/.config/kiwi-proxy/secrets` that only your user can read.
`KIWI_PROXY_SECRETS=keyring` or `KIWI_PROXY_SECRETS=file` forces one of the
two.

A new exit starts with the DNS settings from your preferences (see
[DNS and ad-blocking](dns.md#preferences-for-new-exits)). `--notes TEXT` adds a
note to the exit.

## Bring an exit up and down

```bash
kiwi-proxy up work
kiwi-proxy check work
kiwi-proxy down work
```

`up` starts the gateway, measures which IP address and country the world sees
through it, and keeps it running until you run `down`. `--no-measure` skips the
measurement, and `--replace` starts the gateway again even if it is already up,
which is how a changed setting takes effect. `--json` prints what an app needs
to join the gateway (see [For apps that use exits](consumers.md#cli)).

`down` stops the gateway and removes every member that joined it, because
Podman cannot move a container into another namespace. A member that labels
itself `kiwi-proxy.snapshot=<image>`, such as a kiwi-custodia box, is first
saved to that image and then removed.

`check` measures what the world sees through an exit. If the exit is down,
kiwi-proxy brings it up for the measurement and takes it down again.
`kiwi-proxy test ENDPOINT` measures an endpoint without saving an exit.

## Use an exit from the host

A program on the host does not have to run in a container to use an exit.
`--expose [ADDR:]PORT` publishes the exit's SOCKS5 as a port on the host, one
port for each exit:

```bash
kiwi-proxy add se socks5://10.64.0.1:1080 --expose 1081
kiwi-proxy add nl socks5://10.65.0.1:1080 --expose 1082
kiwi-proxy up se && kiwi-proxy up nl
curl --proxy socks5h://127.0.0.1:1082 https://ifconfig.co/json
```

Point a program at `socks5h://127.0.0.1:PORT`. The `h` means that the program
sends host names to the proxy instead of resolving them itself, so its DNS
queries go through the exit too. A program that uses plain `socks5://`
resolves names on the host, outside the exit.

The port listens on `127.0.0.1` unless you give another address. An address
that other machines can reach needs one of these:

- `--expose-user NAME`: the port demands this user and a password, which you
  are asked for (or which `--expose-password-stdin` reads).
- `--expose-open`: you confirm that the port may be open without a password.

The port is a second listener of the same forwarder inside the gateway, so
whatever a host program sends still leaves only through the exit's upstream.
`kiwi-proxy set NAME --no-expose` stops publishing it.

### Keep an exit up at login

The installer adds a systemd user unit for this:

```bash
systemctl --user enable --now kiwi-proxy@se
```

It runs `kiwi-proxy up --no-measure se` when your systemd user session starts
and `kiwi-proxy down se` when it ends. With `loginctl enable-linger` your user
session, and with it the exit, keeps running while you are not logged in.

## Join a gateway with a container

```bash
kiwi-proxy up work
podman run --rm --network "container:$(kiwi-proxy name work)" \
    docker.io/curlimages/curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.co/json
```

`kiwi-proxy name EXIT` prints the gateway's container name. Inside the
namespace the SOCKS5 forwarder is at `127.0.0.1:1080` and asks members for no
password. A member that should resolve names with the gateway's resolver mounts
the file `up` names at `/etc/resolv.conf`; `kiwi-proxy up` prints the full
`--volume` option.

## Who keeps a gateway up

Several apps can use the same exit at once: two browser profiles, a testing
tool and a host port all share one gateway, the same upstream and the same
DNS. kiwi-proxy hands the running gateway to each of them instead of starting a
second one.

- A gateway that you started with `kiwi-proxy up` stays up until
  `kiwi-proxy down`.
- A gateway that another app started, such as kiwi-fox when you open a
  browser profile, is removed when its last member leaves.
- `kiwi-proxy ps` lists every gateway, whichever app started it.
- `kiwi-proxy reap` removes gateways that have stopped, and running ones that
  have no member, were not started with `up` and publish no host port. It also
  starts a provider container again behind a running gateway when the provider
  has stopped.

## Change and remove an exit

```bash
kiwi-proxy set work --endpoint socks5://user:pass@other.example.net:1080
kiwi-proxy set work --expose 1083
kiwi-proxy up --replace work
kiwi-proxy rm work
```

`set` takes the same options as `add`. A change applies to a running exit only
after `kiwi-proxy up --replace`. `rm` takes the exit down and deletes it. An
exit that another app created, such as a kiwi-fox profile's exit, is removed
only with `--force`.

## Commands

| Command | What it does |
|---|---|
| `add NAME [ENDPOINT]` | Saves an exit. Without an endpoint, `--module` has a provider module create one. |
| `list`, `show EXIT` | Lists the exits, or shows everything about one. Both take `--json`. |
| `set EXIT` | Changes an exit. |
| `rm EXIT` | Takes an exit down and deletes it. |
| `up EXIT` | Starts the exit's gateway and keeps it up. |
| `down EXIT` | Stops the gateway and removes its members. |
| `name EXIT` | Prints the gateway's container name, for `--network container:`. |
| `check EXIT` | Measures what the world sees through the exit. |
| `test ENDPOINT` | Measures an endpoint without saving an exit. |
| `logs EXIT` | Shows the recent log of the exit's gateway and provider containers (`--lines`, default 200). |
| `renew EXIT` | Asks the provider for a new IP address (9proxy). |
| `nyx EXIT` | Opens Tor's monitor, nyx, for a Tor exit that is up. |
| `ps` | Lists every gateway, whichever app started it. |
| `reap` | Removes gateways nobody uses and restarts providers that stopped. |
| `prefs` | Shows and sets what new exits start with, and the countries no Tor exit uses. |
| `dns sync`, `dns update` | Downloads the resolver list, or the blocklists. |
| `module …` | Manages provider modules (see [Provider modules](modules.md#commands)). |
| `snapshot …` | Manages snapshots (see [Snapshots](snapshots.md#commands)). |
| `setup` | Builds the gateway image, downloads the DNS data and prepares the modules. |
| `doctor` | Checks Podman, the password store, the DNS data, the images, the modules and snapshots. |
| `storage check`, `storage repair`, `storage leftovers` | Checks Podman's storage, repairs it, and lists or removes containers that a crash left behind. |

An exit can be named by its name or by the first characters of its id.
`kiwi-proxy COMMAND --help` lists every option of a command.

## When something goes wrong

- `kiwi-proxy doctor` says what is missing.
- `kiwi-proxy logs EXIT` shows why a gateway or its provider did not start.
- **VPN not answering** on a VPN exit means its server does not answer right
  now. The tunnel reconnects by itself once the server answers again, and
  nothing leaves the exit meanwhile. See [VPN exits](modules.md#vpn-exits).
- `kiwi-proxy storage check` runs Podman's quick storage check and names every
  broken container and the app it belongs to. `kiwi-proxy storage repair`
  removes the broken Kiwi containers, and other containers only with
  `--theirs-too`, then lets Podman repair the rest.
- `kiwi-proxy storage leftovers --remove` removes kiwi-proxy containers that a
  crash left in the states "created", "exited" or "dead". `--app kiwi-fox` or
  `--app kiwi-custodia` does the same for those apps.

## The app

The app, `kiwi-proxy-gui` (**Kiwi Proxy** in your app grid), does everything on
this page without a terminal. You can add and edit exits, bring them up and
down, offer an exit as a SOCKS5 port on this computer and copy its address,
check what the world sees through it, see which members joined a gateway, read
the logs of the exit's containers, and set up and configure provider modules.

![A new exit in Kiwi Proxy](images/new-exit.png)

![The details of an exit](images/exit-details.png)

The gear button opens **Preferences** (Ctrl+,): the DNS, Tor, Modules and
Snapshots pages, and **Maintenance** with **Set up environment**, **Check
environment**, **Check and repair** and **Tidy up**. The menu beside it keeps
**Take down the exits made here** and **About**. Small (?) buttons next to
settings explain them and link to this documentation.
