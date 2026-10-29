"""Kill-switch and DNS assertions against a live gateway namespace.

Every one of these was verified by hand on the dev machine before being written
down; they exist so a regression cannot pass silently.
"""

import pytest

from kiwi_proxy import podman

from .conftest import dig_status, sh

# A domain present in oisd big, and one that must keep working.
BLOCKED = "accounts.doubleclick.net"
BLOCKED_APEX = "0-02.net"
ALLOWED = "wikipedia.org"


def test_direct_egress_is_blocked(gateway_name):
    for target in ("1.1.1.1/443", "8.8.8.8/53", "9.9.9.9/443"):
        out = sh(
            gateway_name,
            f'timeout 5 bash -c "echo > /dev/tcp/{target}" 2>/dev/null && echo LEAK || echo blocked',
        )
        assert out == "blocked", f"egress to {target} was not blocked"


def _permitted_destination(gateway_name) -> tuple[str, str]:
    """The address the gateway's firewall actually permits, read from the gateway
    itself. For a plain endpoint this equals the exit's endpoint; for a managed
    local provider it is the provider's live bridge address (resolved at launch),
    which the stored endpoint host does NOT equal — so read the live value rather
    than assuming the two are the same."""
    ip = sh(gateway_name, "printenv KF_ENDPOINT_IP")
    port = sh(gateway_name, "printenv KF_ENDPOINT_PORT")
    return ip, port


def test_the_proxy_endpoint_is_reachable(gateway_name):
    ip, port = _permitted_destination(gateway_name)
    assert ip and port, "gateway is missing KF_ENDPOINT_IP/PORT"
    out = sh(
        gateway_name,
        f'timeout 5 bash -c "echo > /dev/tcp/{ip}/{port}" 2>/dev/null && echo ok || echo unreachable',
    )
    assert out == "ok", "the one permitted destination must be reachable"


def test_only_the_permitted_destination_is_reachable_on_its_segment(gateway_name):
    # On the kf-providers bridge the gateway has on-link neighbours (the bridge's
    # own gateway, sibling provider/gateway containers) that routing alone would
    # not stop — only the nftables default-drop does. Prove a neighbour one address
    # away from the permitted provider is still blocked. (On a plain pasta endpoint
    # this neighbour is simply dropped too, so the assertion holds either way.)
    ip, port = _permitted_destination(gateway_name)
    if ip.count(".") != 3:
        pytest.skip(f"not an IPv4 permitted destination: {ip!r}")
    octets = ip.split(".")
    last = int(octets[3])
    octets[3] = str((last + 1) % 256 if last != 1 else 2)
    neighbour = ".".join(octets)
    out = sh(
        gateway_name,
        f'timeout 5 bash -c "echo > /dev/tcp/{neighbour}/{port}" 2>/dev/null && echo LEAK || echo blocked',
    )
    assert out == "blocked", f"a non-permitted on-link neighbour {neighbour} was reachable"


def test_udp_dns_cannot_leave(gateway_name):
    # SOCKS5 carries no UDP, so nothing should even try; prove it cannot.
    out = sh(gateway_name, "timeout 5 dig +time=3 +tries=1 @8.8.8.8 example.com 2>&1 | tail -1")
    assert "connection timed out" in out or "no servers could be reached" in out, out


def test_nft_is_dropping(gateway_name):
    out = sh(gateway_name, "nft list ruleset | grep -A1 'kf-dropped' | head -2")
    assert "packets" in out
    dropped = int(out.split("packets")[1].split()[0])
    assert dropped > 0, "nothing was dropped; is the ruleset actually loaded?"


def test_resolver_answers_through_the_proxy(gateway_name):
    if not resolver_mode(gateway_name):
        pytest.skip("remote DNS: names resolve at the proxy")
    assert dig_status(gateway_name, ALLOWED) == "NOERROR"
    answer = sh(gateway_name, f"dig +short +time=10 @127.0.0.2 {ALLOWED} | head -1")
    assert answer and answer[0].isdigit(), f"no address for {ALLOWED}: {answer!r}"


@pytest.mark.parametrize("name", [BLOCKED, BLOCKED_APEX])
def test_blocklist_refuses(gateway_name, name):
    if not resolver_mode(gateway_name):
        pytest.skip("remote DNS: names resolve at the proxy")
    assert dig_status(gateway_name, name) == "REFUSED"


def test_blocklist_covers_subdomains(gateway_name):
    if not resolver_mode(gateway_name):
        pytest.skip("remote DNS: names resolve at the proxy")
    # oisd's bare-domain entries must match subdomains too, which is exactly
    # dnscrypt-proxy's bare-name rule and why domainswild2 is the right format.
    assert dig_status(gateway_name, f"deeper.sub.{BLOCKED_APEX}") == "REFUSED"


def resolver_mode(gateway_name) -> bool:
    return sh(gateway_name, "printenv KF_DNS_MODE") == "resolver"


def test_every_member_has_no_network_namespace_of_its_own(gateway_name):
    # A browser, a pentest tool: whoever joined has no routing table to leak with.
    members = podman.dependents(gateway_name)
    if not members:
        pytest.skip("nothing joined this gateway")
    for name in members:
        mode = podman._run(
            ["inspect", name, "--format", "{{.HostConfig.NetworkMode}}"], check=False
        ).stdout.strip()
        assert mode.startswith("container:"), f"{name} must join the gateway netns, got {mode!r}"


def test_the_exit_is_measured_through_the_forwarder(gateway_name):
    from kiwi_proxy import gateway

    info = gateway.measure_exit(gateway_name)
    assert info.ip, "the forwarder did not carry the probe out"


def test_the_host_listener_leaves_through_the_same_exit(running_gateway, gateway_name):
    if not running_gateway["expose"]:
        pytest.skip("this exit is not exposed on the host")
    if sh(gateway_name, "printenv KF_EXPOSE_CREDS_FILE"):
        pytest.skip("the host listener wants a password")
    from kiwi_proxy import endpoint, gateway
    from kiwi_proxy.models import Endpoint

    host, _, port = running_gateway["expose"].rpartition(":")
    via_host = endpoint.preflight(Endpoint(host=host.strip("[]"), port=int(port)))
    assert via_host.ip == gateway.measure_exit(gateway_name).ip


def test_the_host_listener_refuses_blocked_names(running_gateway, gateway_name):
    # socks5h hands the name to the forwarder, past the resolver; the forwarder
    # applies the same list.
    if not running_gateway["expose"] or not resolver_mode(gateway_name):
        pytest.skip("needs an exposed exit in resolver mode")
    if sh(gateway_name, "printenv KF_EXPOSE_CREDS_FILE"):
        pytest.skip("the host listener wants a password")
    from kiwi_proxy import endpoint
    from kiwi_proxy.models import Endpoint

    host, _, port = running_gateway["expose"].rpartition(":")
    ep = Endpoint(host=host.strip("[]"), port=int(port))
    with pytest.raises(endpoint.EndpointError, match="code 2"):
        endpoint.socks5_connect(ep, BLOCKED, 443)
    endpoint.socks5_connect(ep, ALLOWED, 443).close()
