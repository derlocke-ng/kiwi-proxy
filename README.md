# kiwi-proxy

kiwi-proxy is for people who reach several networks through their own VPN or
SOCKS5 connections, for example one connection for each client they work for.
You save each connection as a named **exit** and bring it up only when you need
it. kiwi-proxy then starts a **gateway** for the exit: a rootless Podman
container whose network namespace (a separate network stack with its own routes
and firewall) has exactly one way out, the exit's upstream. Browsers, testing
tools and other containers join that namespace, and programs on the host can
use the exit as a SOCKS5 port. If the gateway stops, everything that uses it
loses its connection, and nothing falls back to a direct connection.

kiwi-proxy is part of the Kiwi desktop. kiwi-fox (browser profiles),
kiwi-custodia (distro boxes) and kiwi-pentesting use its exits, and a
kiwi-server machine can host exits for the whole mesh with the module in this
repository.

- Latest release: **v0.23.0**, in the
  [Kiwi catalog](https://kiwi-network.eu/docs/desktop/catalogs/) (user scope,
  no root needed)
- Runs on: Linux with rootless Podman and Python 3.12 or newer. CI runs the
  unit tests on Ubuntu 24.04 and starts the gateway image with Podman.
- License: GPL-3.0-or-later

![The list of exits in Kiwi Proxy](data/screenshots/1-exits.png)

## Install

```bash
kiwi install kiwi-proxy
kiwi-proxy setup
```

`kiwi install` puts kiwi-proxy under `~/.local` and adds the `kiwi-proxy`
command, the **Kiwi Proxy** app and a few systemd user units. Nothing is
installed as root. `kiwi-proxy setup` builds the gateway image, downloads the
DNS data and prepares the images of the provider modules you installed. Run it
once after the install. From a checkout, `./install.sh install` does the same
as `kiwi install`. The [install page](docs/install.md) lists what kiwi-proxy
needs and every file it writes.

## Quick start

```bash
kiwi-proxy add work socks5://user:pass@proxy.example.net:1080 --expose 1081
kiwi-proxy up work
curl --proxy socks5h://127.0.0.1:1081 https://ifconfig.co/json
kiwi-proxy down work
```

`add` saves the exit and stores the password in your keyring, or in a file
only you can read on a machine without one. `up` starts the
exit's gateway, publishes its SOCKS5 port on `127.0.0.1:1081` and keeps it
running until `down`. The `h` in `socks5h` makes `curl` send host names
through the exit as well, so DNS queries cannot bypass it. The app,
`kiwi-proxy-gui` (**Kiwi Proxy** in your app grid), does the same without a
terminal.

## Documentation

| Page | What it covers |
|---|---|
| [Install](docs/install.md) | requirements, install, first setup, update, uninstall |
| [Using kiwi-proxy](docs/usage.md) | exits, every command, host ports, the app |
| [Provider modules](docs/modules.md) | Tor, VPN, 9proxy and Mysterium exits |
| [DNS and ad-blocking](docs/dns.md) | how an exit resolves names and which it refuses |
| [Snapshots](docs/snapshots.md) | your exits on your other devices, encrypted |
| [On a kiwi-server machine](docs/kiwi-server.md) | exits for the whole mesh |
| [For apps that use exits](docs/consumers.md) | the Python API and `--json` for other apps |
| [Writing a provider module](docs/plugin-system.md) | the contract a module keeps |
| [Architecture](docs/architecture.md) | gateways, members, labels, files |
| [Decisions](docs/decisions.md) | why things are the way they are |
| [Development](docs/development.md) | tests, CI, releases |

The same pages are on
[kiwi-network.eu](https://kiwi-network.eu/docs/clients/kiwi-proxy/).

## License

GPL-3.0-or-later; see [LICENSE](LICENSE).
