#!/usr/bin/env bash
# The gateway image, started as kiwi-proxy starts it, against a dummy SOCKS5.
#
# The unit tests passed while no gateway could start at all (0.2.0: the forwarder
# crashed on the empty credentials path of every gateway without a host listener),
# because nothing ever ran the container. This does, the way gateway_spec() renders
# it — the credentials as a podman secret, every capability dropped but NET_ADMIN
# and NET_BIND_SERVICE, no-new-privileges, remote DNS so no resolver config is
# needed — on a bridge with a SOCKS5 upstream that demands the credentials the
# secret holds, and checks both ways a gateway is started:
#
#   1. without a host listener (every kiwi-fox gateway): it reports ready, stays
#      up, relays a member's CONNECT, and drops everything else;
#   2. with a password-guarded host listener: the published port relays with the
#      password and refuses a client without one.
#
#   tests/smoke/gateway.sh [IMAGE]        default kiwi-proxy/gateway:smoke
#
# Needs podman only, rootless as kiwi-proxy runs it, and no kiwi-proxy install.
# ci.yml builds the image with --no-cache first; `make smoke` builds it with the
# cache and runs this.
set -euo pipefail

IMAGE="${1:-kiwi-proxy/gateway:smoke}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET=kf-smoke
UPSTREAM=kf-smoke-upstream
GW=kf-smoke-gw
CREDS=kf-smoke-creds           # the exit's credentials, as kiwi-proxy stores them
EXPOSE_CREDS=kf-smoke-expose   # the host listener's password
FORWARDER_PORT=1080            # gateway.FORWARDER_PORT
EXPOSE_PORT=1081               # gateway.EXPOSE_PORT

say() { printf '\n== %s\n' "$*"; }
fail() {
    printf 'smoke: FAIL: %s\n' "$*" >&2
    for c in "$GW" "$UPSTREAM"; do
        if podman container exists "$c" 2>/dev/null; then
            printf -- '--- podman logs %s\n' "$c" >&2
            podman logs "$c" >&2 2>&1 || true
        fi
    done
    exit 1
}
cleanup() {
    podman rm -f -t 0 "$GW" "$UPSTREAM" >/dev/null 2>&1 || true
    podman secret rm "$CREDS" "$EXPOSE_CREDS" >/dev/null 2>&1 || true
    podman network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The container is running and reports ready, within 30 s. An exit before that is
# the failure this exists to catch, so it is reported with the logs.
wait_ready() {
    local name=$1 i
    for i in $(seq 1 60); do
        [ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] \
            || fail "$name exited during startup"
        if podman logs "$name" 2>&1 | grep -qF 'the namespace is sealed'; then
            return 0
        fi
        sleep 0.5
    done
    fail "$name did not report ready within 30 s"
}
still_running() {
    [ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] \
        || fail "$1 exited after reporting ready"
}
# python3 from the gateway image, for the upstream and the member-side probe: no
# other image to pull, and the scripts are passed as code so nothing is mounted.
in_image() {  # ARGS... -- SCRIPT SCRIPT-ARGS...
    local run_args=()
    while [ "$1" != -- ]; do run_args+=("$1"); shift; done
    shift
    local script=$1; shift
    podman run "${run_args[@]}" --entrypoint python3 "$IMAGE" -c "$(cat "$HERE/$script")" "$@"
}
gateway() {  # extra podman run args
    # gateway_spec(): dropped capabilities, no userns flag (container-root
    # configures its own netns), the credentials as a mounted secret.
    podman run --detach --name "$GW" --network "$NET" \
        --cap-drop all --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges \
        --env KF_ENDPOINT_IP="$UPSTREAM_IP" --env KF_ENDPOINT_PORT=1080 \
        --env KF_FORWARDER_PORT="$FORWARDER_PORT" --env KF_DNS_MODE=remote \
        --env KF_CREDS_FILE=/run/secrets/"$CREDS" \
        --secret "$CREDS,type=mount,target=/run/secrets/$CREDS" \
        "$@" "$IMAGE" >/dev/null
}

cleanup
say "image $IMAGE"
podman image exists "$IMAGE" || fail "no image $IMAGE; build it first (make smoke)"

say "a bridge with a SOCKS5 upstream that wants the exit's credentials"
podman network create --disable-dns "$NET" >/dev/null
in_image --detach --name "$UPSTREAM" --network "$NET" -- socks5_dummy.py 1080 kf-tok exitpw >/dev/null
printf 'kf-tok\nexitpw\n' | podman secret create "$CREDS" - >/dev/null
printf 'me\nhunter2\n' | podman secret create "$EXPOSE_CREDS" - >/dev/null
for _ in $(seq 1 20); do
    UPSTREAM_IP="$(podman inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$UPSTREAM" 2>/dev/null || true)"
    [ -n "$UPSTREAM_IP" ] && break
    sleep 0.5
done
[ -n "${UPSTREAM_IP:-}" ] || fail "the upstream got no address on $NET"
echo "upstream at $UPSTREAM_IP:1080"

say "1. a gateway without a host listener, as every kiwi-fox profile gets one"
gateway
wait_ready "$GW"
echo "ready; a member relays through it and reaches nothing else"
in_image --rm --network "container:$GW" -- socks5_probe.py relay 127.0.0.1 "$FORWARDER_PORT" \
    || fail "a member could not relay through the gateway"
in_image --rm --network "container:$GW" -- socks5_probe.py dropped "$UPSTREAM_IP" 9 \
    || fail "the namespace is not sealed"
still_running "$GW"
podman rm -f -t 0 "$GW" >/dev/null

say "2. a gateway with a password-guarded host listener on a published port"
gateway --env KF_EXPOSE_PORT="$EXPOSE_PORT" \
    --env KF_EXPOSE_CREDS_FILE=/run/secrets/"$EXPOSE_CREDS" \
    --secret "$EXPOSE_CREDS,type=mount,target=/run/secrets/$EXPOSE_CREDS" \
    --publish "127.0.0.1::$EXPOSE_PORT/tcp"
wait_ready "$GW"
HOST_PORT="$(podman port "$GW" "$EXPOSE_PORT/tcp" | head -1 | sed 's/.*://')"
[ -n "$HOST_PORT" ] || fail "no published port for $EXPOSE_PORT"
echo "ready; published on 127.0.0.1:$HOST_PORT"
python3 "$HERE/socks5_probe.py" relay 127.0.0.1 "$HOST_PORT" me hunter2 \
    || fail "the host listener did not relay with the password"
python3 "$HERE/socks5_probe.py" refused 127.0.0.1 "$HOST_PORT" \
    || fail "the host listener let a client without the password in"
still_running "$GW"

say "gateway logs"
podman logs "$GW" 2>&1
say "ok: the gateway comes up and relays, with and without a host listener"
