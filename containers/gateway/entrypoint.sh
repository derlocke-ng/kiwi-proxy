#!/usr/bin/env bash
# kiwi-proxy gateway — build a network namespace whose only exit is one SOCKS5
# upstream, then hold it open for containers to join and, optionally, publish
# its SOCKS5 on the host.
#
# A member joins with --network container:<this> and so has no network
# namespace, no routing table and no interfaces of its own. If this container
# dies every member loses connectivity: the kill switch is the absence of a
# route, not software that has to notice.
#
#   KF_UPSTREAM        "direct": a tunnel exit (a VPN). This container joined the
#                      tunnel's namespace, whose firewall (gluetun's) is the kill
#                      switch and whose route is the tunnel; the forwarder connects
#                      targets itself. No endpoint, and gluetun's rules stay.
#   KF_ENDPOINT_IP     the one permitted destination, a literal address
#   KF_ENDPOINT_HOST   instead of KF_ENDPOINT_IP, a name resolved here once,
#                      before the firewall goes up (kiwi-server machines, where
#                      no host-side tool resolves it first)
#   KF_ENDPOINT_PORT   its port
#   KF_FORWARDER_PORT  the members' SOCKS5 on 127.0.0.1 (1080)
#   KF_EXPOSE_PORT     a second SOCKS5 on 0.0.0.0, for the host to publish
#   KF_DNS_MODE        resolver (dnscrypt-proxy on 127.0.0.2) | remote
#   KF_BLOCKLIST       names the forwarder refuses (the resolver's list, or below)
#   KF_BLOCKLIST_URLS  lists to fetch through this exit, daily, into KF_BLOCKLIST
#                      (kiwi-server machines: no host-side tool downloads them)
set -euo pipefail

log() { printf 'gateway: %s\n' "$*"; }
die() { printf 'gateway: FATAL: %s\n' "$*" >&2; exit 1; }

KF_UPSTREAM="${KF_UPSTREAM:-socks}"
if [ "$KF_UPSTREAM" = direct ]; then
    : "${KF_ENDPOINT_IP:=}" "${KF_ENDPOINT_PORT:=0}"
elif [ -z "${KF_ENDPOINT_IP:-}" ] && [ -n "${KF_ENDPOINT_HOST:-}" ]; then
    KF_ENDPOINT_IP="$(getent ahostsv4 "$KF_ENDPOINT_HOST" | awk 'NR == 1 { print $1 }')"
    [ -n "$KF_ENDPOINT_IP" ] || die "cannot resolve $KF_ENDPOINT_HOST"
    log "resolved $KF_ENDPOINT_HOST -> $KF_ENDPOINT_IP (before sealing)"
    export KF_ENDPOINT_IP
fi
if [ "$KF_UPSTREAM" != direct ]; then
    : "${KF_ENDPOINT_IP:?KF_ENDPOINT_IP (or KF_ENDPOINT_HOST) is required}"
    : "${KF_ENDPOINT_PORT:?KF_ENDPOINT_PORT is required}"
fi
KF_FORWARDER_PORT="${KF_FORWARDER_PORT:-1080}"
KF_EXPOSE_PORT="${KF_EXPOSE_PORT:-}"
KF_DNS_MODE="${KF_DNS_MODE:-resolver}"
RESOLVER_CFG=/run/kf/dnscrypt-proxy.toml

case "$KF_EXPOSE_PORT" in *[!0-9]*) die "KF_EXPOSE_PORT must be a port number";; esac
EXPOSE_RULE=""
if [ -n "$KF_EXPOSE_PORT" ]; then
    # Inbound connections to the host listener. Replies ride ct established;
    # what the listener relays still leaves only by the output rule.
    EXPOSE_RULE="tcp dport ${KF_EXPOSE_PORT} accept"
fi

case "$KF_ENDPOINT_IP" in
  *[a-zA-Z]*) die "endpoint must be a literal address (resolution happens on the host)";;
esac

# ---------------------------------------------------------------- firewall
# Rules key on destination, not on sending uid: a uid-matched exemption breaks
# silently if a relay drops privileges differently than expected.
# A Tor exit for Tor Browser: its Tor's control port, behind the forwarder's filter.
CONTROL_RULE=""
if [ -n "${KF_CONTROL_IP:-}" ]; then
    CONTROL_RULE="ip daddr ${KF_CONTROL_IP} tcp dport ${KF_CONTROL_PORT:-9052} accept"
fi
if [ "$KF_UPSTREAM" = direct ]; then
    # The tunnel's own firewall (gluetun's) allows only the tunnel and its server:
    # it stays as it is, nothing here flushes it.
    log "firewall: the tunnel's own (its kill switch); traffic leaves only through the tunnel"
else
log "firewall: default drop, permitting only ${KF_ENDPOINT_IP}:${KF_ENDPOINT_PORT}${KF_CONTROL_IP:+ and ${KF_CONTROL_IP}:${KF_CONTROL_PORT:-9052} (Tor control)}"
nft -f - <<EOF
flush ruleset

table inet kiwiproxy {
  chain output {
    type filter hook output priority filter; policy drop;

    ct state established,related accept
    oif "lo" accept

    # The one permitted destination.
    ip daddr ${KF_ENDPOINT_IP} tcp dport ${KF_ENDPOINT_PORT} accept
    ${CONTROL_RULE}

    # Everything else is dropped: no direct TCP, no UDP (so no QUIC and no
    # WebRTC media), no plaintext DNS, no ICMP, no IPv6.
    counter comment "kf-dropped"
  }

  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    iif "lo" accept
    ${EXPOSE_RULE}
  }
}
EOF
fi

# --------------------------------------------------------------- forwarder
log "forwarder: starting on 127.0.0.1:${KF_FORWARDER_PORT}"
python3 /usr/local/bin/kf-forwarder &
FORWARDER_PID=$!

# The gate must not open before the relay accepts connections, or there is a
# window where traffic is redirected into a dead port.
ready=false
for _ in $(seq 1 100); do
    kill -0 "$FORWARDER_PID" 2>/dev/null || die "forwarder exited during startup"
    if (exec 3<>"/dev/tcp/127.0.0.1/${KF_FORWARDER_PORT}") 2>/dev/null; then
        ready=true; break
    fi
    sleep 0.1
done
[ "$ready" = true ] || die "forwarder never listened on :${KF_FORWARDER_PORT}"
log "forwarder: listening"
if [ -n "$KF_EXPOSE_PORT" ]; then
    ready=false
    for _ in $(seq 1 100); do
        kill -0 "$FORWARDER_PID" 2>/dev/null || die "forwarder exited during startup"
        if (exec 3<>"/dev/tcp/127.0.0.1/${KF_EXPOSE_PORT}") 2>/dev/null; then
            ready=true; break
        fi
        sleep 0.1
    done
    [ "$ready" = true ] || die "host listener never listened on :${KF_EXPOSE_PORT}"
    log "forwarder: host listener on :${KF_EXPOSE_PORT}"
fi

# ---------------------------------------------------------------- resolver
RESOLVER_PID=""
# One A query for example.com at the resolver; exit 0 when it answers with one.
RESOLVER_PROBE='
import socket, struct
q = struct.pack("!6H", 0x4B1D, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!2H", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(q, ("127.0.0.2", 53))
d = s.recv(512)
raise SystemExit(0 if d[3] & 0x0F == 0 and struct.unpack("!H", d[6:8])[0] > 0 else 1)
'
if [ "$KF_DNS_MODE" = resolver ]; then
    [ -f "$RESOLVER_CFG" ] || die "resolver mode but $RESOLVER_CFG is missing"
    log "resolver: dnscrypt-proxy on 127.0.0.2:53, upstream DoH through the forwarder"
    dnscrypt-proxy -config "$RESOLVER_CFG" &
    RESOLVER_PID=$!
    # Ready means it answers a name, asked directly at 127.0.0.2 — not through
    # this container's resolv.conf (podman's, which the firewall blocks; in a
    # VPN's namespace the tunnel's own resolver, which is off).
    answered=false
    for _ in $(seq 1 60); do
        kill -0 "$RESOLVER_PID" 2>/dev/null || die "dnscrypt-proxy exited during startup"
        if python3 -c "$RESOLVER_PROBE" 2>/dev/null; then answered=true; break; fi
        sleep 0.5
    done
    if [ "$answered" = true ]; then log "resolver: up"; else log "resolver: no answer yet; going on"; fi
else
    log "resolver: disabled (remote DNS at the proxy)"
fi

# ------------------------------------------------------------- blocklists
FETCHER_PID=""
if [ -n "${KF_BLOCKLIST_URLS:-}" ]; then
    : "${KF_BLOCKLIST:?KF_BLOCKLIST_URLS needs KF_BLOCKLIST, the file to write}"
    fetch_lists() {
        local merged="${KF_BLOCKLIST}.new" part="${KF_BLOCKLIST}.part" url
        : > "$merged"
        for url in $KF_BLOCKLIST_URLS; do
            kf-exitinfo --out "$part" "$url" || { rm -f "$merged" "$part"; return 1; }
            cat "$part" >> "$merged"
        done
        rm -f "$part"
        mv "$merged" "$KF_BLOCKLIST"
        log "blocklists: $(wc -l < "$KF_BLOCKLIST") names, fetched through the exit"
    }
    # Daily, and every ten minutes until the first fetch works. The forwarder
    # picks a new file up by itself.
    ( while true; do
          if fetch_lists; then sleep 86400; else sleep 600; fi
      done ) &
    FETCHER_PID=$!
fi

cleanup() {
    log "shutting down"
    [ -n "$FETCHER_PID" ] && kill "$FETCHER_PID" 2>/dev/null || true
    [ -n "$RESOLVER_PID" ] && kill "$RESOLVER_PID" 2>/dev/null || true
    kill "$FORWARDER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

log "ready — the namespace is sealed"

# Hold the namespace open, and die if either service dies so every member loses
# its route rather than silently running without one.
while true; do
    sleep 5
    kill -0 "$FORWARDER_PID" 2>/dev/null || die "forwarder died"
    if [ -n "$RESOLVER_PID" ]; then
        kill -0 "$RESOLVER_PID" 2>/dev/null || die "resolver died"
    fi
done
