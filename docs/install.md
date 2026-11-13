# Install

This page says what kiwi-proxy needs, how to install it, what the first setup
does, and how to update and remove it. kiwi-proxy is installed for your own
user only. It needs no root rights, because its containers run in rootless
Podman, which means Podman containers that run as your own user.

## What you need

| What | Why |
|---|---|
| Linux with rootless Podman | Every gateway and provider is a Podman container that runs as your user. |
| Python 3.12 or newer, with pydantic 2.6 or newer | The command and the app are written in Python. |
| GTK 4, libadwaita and PyGObject | Only for the app, **Kiwi Proxy**. A machine without a desktop can do without them. |
| `secret-tool` (optional) | Passwords go to your desktop keyring through it. Without it, they go to files that only your user can read (mode 0600). |
| `gpg` and `zstd` (optional) | Only for [snapshots](snapshots.md). Everything else works without them. |

`kiwi` checks for `podman` and `python3` before it installs kiwi-proxy. It
does not install pydantic or the GTK libraries for you.

## Supported systems

kiwi-proxy belongs to the Kiwi desktop, a Fedora Atomic workstation. These are
the systems that are tested automatically:

| What is tested | Where |
|---|---|
| Unit tests, including the app's windows under Xvfb, and the linter | GitHub Actions, Ubuntu 24.04 with its Python 3.12 |
| The gateway image: built without a cache, started with and without a host port, against a test SOCKS5 proxy | GitHub Actions, Ubuntu with rootless Podman |

The leak tests in `tests/leak` need a running gateway and are not run in CI.
No other distribution is tested automatically yet.

## Install with kiwi

```bash
kiwi install kiwi-proxy
kiwi-proxy setup
```

kiwi-proxy is in the [Kiwi catalog](https://kiwi-network.eu/docs/desktop/catalogs/)
with user scope. `kiwi install kiwi-fox` and `kiwi install kiwi-custodia`
install it too, because both depend on it, and kiwi-fox's own setup runs
`kiwi-proxy setup` for you.

## Install from a checkout

```bash
git clone https://github.com/derlocke-ng/kiwi-proxy
cd kiwi-proxy
./install.sh install
kiwi-proxy setup
```

`install.sh` reads these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `KIWI_PREFIX` | `~/.local` | Where the program, the commands and the app entry go. |
| `KIWI_GUI` | `1` | `0` installs without the app, for a machine without a desktop. |
| `KIWI_SCOPE` | `user` | Any other scope is refused: kiwi-proxy is a user app only. |

## What the installer writes

| Path | What it is |
|---|---|
| `~/.local/lib/kiwi-proxy/` | The Python package, the gateway's container files and the kiwi-server module. |
| `~/.local/bin/kiwi-proxy` | The command. |
| `~/.local/bin/kiwi-proxy-gui` | The app (not with `KIWI_GUI=0`). |
| `~/.local/share/applications/eu.kiwinetwork.KiwiProxy.desktop` and its icon | The app's entry in your app grid. |
| `~/.config/systemd/user/kiwi-proxy-blocklists.timer` and `.service` | Download the blocklists once a day. The timer is enabled at install. |
| `~/.config/systemd/user/kiwi-proxy@.service` | Keeps one exit up while you are logged in, once you enable it for that exit (see [Using kiwi-proxy](usage.md#keep-an-exit-up-at-login)). |

If kiwi-fox had already downloaded DNS data before kiwi-proxy existed as its
own app, the installer copies it instead of downloading it again.

## First setup

`kiwi-proxy setup` prepares everything an exit needs before it can come up. It
is not part of the install because it downloads a lot. It is safe to run again
at any time.

1. It builds the gateway image, `kiwi-proxy/gateway:latest`, from
   `containers/gateway/Containerfile`. The image is based on Fedora 43 and
   downloads its packages from Fedora's servers.
2. It downloads the list of DNS-over-HTTPS resolvers from
   `download.dnscrypt.info` and keeps the entries kiwi-proxy uses.
3. It downloads the default blocklist, oisd big.
4. It builds or pulls the image of every provider module you installed.

`kiwi-proxy doctor` checks the result: Podman, where passwords are kept, the
DNS data, the gateway image, your exits, your modules and snapshots.

## Update

`kiwi update` updates kiwi-proxy like every other Kiwi app. An update runs the
same steps as an install. When the new version changed the gateway image's
files, the image is rebuilt the next time an exit comes up. If that rebuild
fails, the exit does not start, and the error tells you to run
`kiwi-proxy setup`.

## Uninstall

```bash
kiwi uninstall kiwi-proxy            # or: ./install.sh uninstall
kiwi uninstall kiwi-proxy --purge    # or: ./install.sh uninstall --purge
```

An uninstall removes the program, the commands, the app entry and the systemd
units. It keeps your exits, the module settings and the stored passwords in
`~/.local/share/kiwi-proxy` and `~/.config/kiwi-proxy`, so a new install
continues where you left off. `--purge` deletes those two folders as well.
Passwords stored in your desktop keyring stay there.
