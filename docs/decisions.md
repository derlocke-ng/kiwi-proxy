# Decisions

Why things are the way they are. Each entry is a decision that cost something to
reach, so that it is not silently undone later. The network entries were kiwi-fox's
before the split and are carried over word for word where they still hold.

## The split

**The proxy engine is its own app.** kiwi-fox grew a full SOCKS5/VPN tunnelling
suite — gateways, a forwarder, a resolver, four provider plugins — that had nothing
to do with browsers except that a browser was its only member. kiwi-pentesting
already joined its tools to those gateways, people with several VPNs wanted the
same exits on the host, and kiwi-server machines wanted to host them for the mesh.
So the engine moved here and kiwi-fox became one consumer of it.

**An exit is the unit, not a profile.** A gateway used to be keyed on a kiwi-fox
profile. Now it is keyed on an exit, which any consumer can create; kiwi-fox makes
one per profile *under the profile id*, so the gateway name (`kf-gw-<id[:12]>`) and
the Tor isolation token (`kf-<id[:16]>`) are byte-for-byte what they were, and a
running identity keeps its circuit across the upgrade.

**Podman names keep `kf-`.** The `kf-providers` bridge has a fixed subnet
(10.89.231.0/24) and rootless podman refuses a second network on a subnet in use,
so a renamed bridge could not be created on any host that ran kiwi-fox. Rather than
migrate a network under running containers, every podman object keeps its name;
labels (`kiwi-proxy.role`, …) say what a container is. Images, which are rebuilt by
setup anyway, moved to `kiwi-proxy/…`.

**The `app` label is the consumer's.** kiwi-proxy finds its containers by
`kiwi-proxy.role`. `app` stays whatever the consumer sets, so kiwi-fox's gateways
are still `app=kiwi-fox`, `kiwi-fox.role=gateway` — what kiwi-pentesting discovers
today — without kiwi-pentesting changing first.

**A gateway is shared, so it is reused, not replaced.** Inside kiwi-fox every
launch replaced the gateway, which was fine with one member. With several (a browser
and a pentest tool on one identity) replacing it would cut the others off. So `up()`
hands back a gateway already running with the same settings (a hash of its rendered
spec in a label), replaces a differently configured one only when nobody is inside
it, and `release()` tears it down only when the last member has left — unless it is
held (`kiwi-proxy up`) for a headless consumer.

**Secrets fall back to files.** kiwi-fox required the Secret Service. A proxy host
is often headless, so without `secret-tool` passwords go to 0600 files under
`~/.config/kiwi-proxy/secrets`; `KIWI_PROXY_SECRETS` forces either. A consumer with
its own keyring (kiwi-fox) passes the password to `up()` instead.

## Network

**The gateway owns the network namespace; members join it.** The kill switch is
then the absence of a route rather than software that has to notice. Measured
working rootless.

**Credentials arrive as a podman secret.** Not container env (`podman inspect` shows
it) and not a bind-mounted 0600 file (the gateway runs as container-root, a subuid,
and cannot read a file owned by the host user). On a kiwi-server machine, which runs
rootful and renders one file for all of a host's exits, a root-owned 0600 table is
mounted instead and each gateway reads its own row.

**Every provider exposes SOCKS5 and nothing else.** Adapting is the module's job, so
the gateway, forwarder, firewall rule and DNS design stay single-shaped.

**The forwarder can inject the exit credential, or pass a client's own through.** By
default (`KF_SOCKS_AUTH=inject`) the gateway's SOCKS5 forwarder answers a member with
no-auth and adds the one per-exit credential upstream, which is all Camoufox, stock
Firefox and tools need. Tor Browser is different: it puts a SOCKS username and
password on every request — the first-party domain and a per-domain nonce — to key a
circuit per site, and its SOCKS client offers *only* username/password, so a no-auth
answer refuses the connection outright. So passthrough mode accepts the client's
credentials and sends upstream the exit token prefixed to the client username
(folded to a hash when the pair would exceed 255 bytes), keeping Tor's
`IsolateSOCKSAuth` per-site circuits while the token still isolates exits. New
Identity and New Circuit then work through the SOCKS nonce alone, with no control
port. Passthrough is an exit setting (`Exit.socks_auth`), set only for a Tor Browser
profile's exit; every other forwarder is byte-for-byte as before.

**The host listener is the same forwarder, behind its own door.** Publishing an
exit on the host could have meant a second proxy process outside the namespace.
Instead the forwarder listens a second time inside it, on 1081, and podman publishes
that port: whatever a host client sends still leaves only through the one permitted
destination, and the input chain gains exactly one rule. A non-loopback bind needs a
password (RFC 1929) or an explicit `--expose-open`; on that listener the
credentials are a gate, checked and then replaced by the exit's own, never an
isolation key.

**A provider module is a plugin, discovered on disk, not code baked in here.** Each
provider — tor, vpn, 9proxy, mysterium — ships in its own repository and installs
under `modules_dir()`. kiwi-proxy loads a module's `provider.py` by file path, not by
import name, so a module named `9proxy` (not a legal Python identifier) still loads.
See `docs/plugin-system.md`.

**A local provider meets the gateway on a bridge, never in its netns.** A provider
that runs its own container needs an unrestricted exit of its own, which the
gateway's default-drop would strand if they shared a namespace. So both attach to
one `kf-providers` bridge and the gateway permits exactly the provider's address on
it — the single-destination firewall rule is unchanged, only the address now points
at a container instead of a public proxy. A plain remote endpoint keeps pasta and
reaches its public address directly.

**A provider exit is measured from inside.** The host is not on the rootless bridge,
so it cannot pre-flight a provider. `kf-exitinfo` asks an ip-echo service through
the forwarder from inside the gateway, which works the same for every exit.

**No EDNS Client Subnet.** The resolver and the members share one exit, so the
upstream already sees the right location.

## kiwi-server

**On a server the gateway resolves its own upstream, once, before sealing.** On a
desktop the host resolves the endpoint and hands the gateway a literal address. A
kiwi-server machine has no host-side kiwi-proxy, so `KF_ENDPOINT_HOST` is resolved
by the entrypoint before the firewall goes up; after that the gateway has no DNS
except through the exit.

**Server gateways get static addresses.** kiwi-server gives every module one fixed
address on the stack network, and a container with a dynamic address could take one
a later module needs. So exits take consecutive addresses from `ip_offset` (.200),
clear of the address plan.
