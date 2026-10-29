"""kiwi-proxy — sealed SOCKS5/VPN exits in rootless Podman, for browsers, tools and hosts.

The proxy engine kiwi-fox used to carry: gateways (a network namespace whose only
route is one upstream), the credential forwarder, the in-namespace resolver, and the
provider plugins (tor, vpn, 9proxy, mysterium). kiwi-fox joins its browser to a
gateway, kiwi-pentesting its tool containers, and any application on the host can
use an exit's published SOCKS5.

The Python API consumers use:

    from kiwi_proxy import exits, gateway
    ex = exits.resolve_ref("work")
    gw = gateway.up(ex)                 # -> gateway.Gateway
    podman run --network container:{gw.name} ...
    gateway.release(ex.id)              # done with it; torn down if nobody else uses it
"""

__version__ = "0.1.0"
