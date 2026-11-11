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

__version__ = "0.14.0"
# The GTK application's id. The desktop entry and the icon are named after it
# (data/<id>.desktop, <id>.svg), which is how GNOME on Wayland connects the
# window to its entry: the app-id of the window is this string.
APP_ID = "eu.kiwinetwork.KiwiProxy"
