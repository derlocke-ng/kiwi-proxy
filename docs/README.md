# kiwi-proxy documentation

kiwi-proxy keeps each of your VPN and SOCKS5 connections apart. An **exit** is
one such connection, saved under a name. A **gateway** is the container that
runs while an exit is up: its network namespace has exactly one way out, the
exit's upstream. A **member** is a container that joined a gateway's namespace,
such as a kiwi-fox browser or a testing tool. A **provider module** creates an
upstream for you, through Tor, a VPN, 9proxy or Mysterium.

| Page | For | What it covers |
|---|---|---|
| [Install](install.md) | everyone | requirements, install, first setup, update, uninstall |
| [Using kiwi-proxy](usage.md) | everyone | exits, every command, host ports, the app |
| [Provider modules](modules.md) | everyone | Tor, VPN, 9proxy and Mysterium exits |
| [DNS and ad-blocking](dns.md) | everyone | how an exit resolves names and which names it refuses |
| [Snapshots](snapshots.md) | everyone with several devices | encrypted copies of your exits for your other devices |
| [On a kiwi-server machine](kiwi-server.md) | administrators | exits for the whole mesh, published on a node or the master |
| [For apps that use exits](consumers.md) | app authors | the Python API and the `--json` output |
| [Writing a provider module](plugin-system.md) | module authors | the contract a provider module keeps |
| [Architecture](architecture.md) | contributors | how a gateway is built, kept up and torn down |
| [Decisions](decisions.md) | contributors | why things are the way they are |
| [Development](development.md) | contributors | tests, CI, releases |

These pages are also on
[kiwi-network.eu](https://kiwi-network.eu/docs/clients/kiwi-proxy/), where
they are pulled from this folder at every release.
