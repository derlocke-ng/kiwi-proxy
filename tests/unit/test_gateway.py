"""The gateway lifecycle against a fake podman: specs, reuse, release, reap.

The fake keeps a table of containers so the tests can say who joined whom; the
real namespace behaviour is the leak suite's job (tests/leak).
"""

from __future__ import annotations

import subprocess

import pytest
from test_providers import install_module

from kiwi_proxy import dns, gateway, paths, podman, providers
from kiwi_proxy.models import DnsConfig, Expose


class FakePodman:
    def __init__(self, monkeypatch):
        self.containers: dict[str, dict] = {}
        self.secrets: dict[str, str] = {}
        self.started: list[str] = []
        self.removed: list[str] = []
        self.provider_ip = "10.89.231.7"
        m = monkeypatch
        m.setattr(podman, "available", lambda: True)
        m.setattr(podman, "is_running", lambda n: self.containers.get(n, {}).get("running", False))
        m.setattr(podman, "exists", lambda n: n in self.containers)
        m.setattr(podman, "labels", lambda n: dict(self.containers.get(n, {}).get("labels", {})))
        m.setattr(podman, "dependents", self.dependents)
        m.setattr(podman, "rm", self.rm)
        m.setattr(podman, "start", self.start)
        m.setattr(podman, "logs", lambda n, tail=50: gateway.READY_MARK)
        m.setattr(podman, "secret_set", lambda n, v: self.secrets.__setitem__(n, v))
        m.setattr(podman, "secret_rm", lambda n: self.secrets.pop(n, None))
        m.setattr(podman, "ps", self.ps)
        m.setattr(podman, "network_ensure", lambda name, **k: None)
        m.setattr(
            podman,
            "container_ip",
            lambda n, net: self.provider_ip if n in self.containers else None,
        )
        m.setattr(
            podman, "container_env", lambda n, k: self.containers.get(n, {}).get("env", {}).get(k)
        )
        m.setattr(
            podman,
            "exec_",
            lambda n, args, timeout=60: subprocess.CompletedProcess(
                args, 0, stdout='{"ip": "198.51.100.7", "country_iso": "SE"}', stderr=""
            ),
        )

    def start(self, spec, **k):
        self.started.append(spec.name)
        self.containers[spec.name] = {
            "running": True,
            "labels": dict(spec.labels),
            "env": dict(spec.env),
            "network": spec.network,
            "spec": spec,
        }
        return "cid"

    def rm(self, name, **k):
        if name in self.containers:
            self.removed.append(name)
            del self.containers[name]

    def dependents(self, name):
        return [n for n, c in self.containers.items() if c["network"] == f"container:{name}"]

    def join(self, name, gw, *, running=True):
        self.containers[name] = {
            "running": running,
            "labels": {},
            "env": {},
            "network": f"container:{gw}",
        }

    def ps(self, all_=True, *, labels=None):
        out = []
        for name, c in self.containers.items():
            if paths.ROLE_LABEL not in c["labels"]:
                continue
            if labels and any(c["labels"].get(k) != v for k, v in labels.items()):
                continue
            if not all_ and not c["running"]:
                continue
            out.append(
                {
                    "Names": [name],
                    "Labels": c["labels"],
                    "State": "running" if c["running"] else "exited",
                }
            )
        return out


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setattr(gateway.endpoint, "resolve", lambda host: host)
    monkeypatch.setattr(
        gateway.endpoint, "preflight", lambda ep, pw=None: (_ for _ in ()).throw(OSError("offline"))
    )
    return FakePodman(monkeypatch)


def remote(new_exit, **kw):
    return new_exit(dns=DnsConfig(mode="remote"), **kw)


# --------------------------------------------------------------------- specs
def test_spec_stays_on_pasta_for_a_plain_endpoint(new_exit):
    spec = gateway.gateway_spec(new_exit(), "203.0.113.9")
    assert spec.network == "pasta"
    assert spec.image == paths.GATEWAY_IMAGE == "kiwi-proxy/gateway:latest"
    assert spec.env["KF_ENDPOINT_IP"] == "203.0.113.9"
    assert spec.env["KF_ENDPOINT_PORT"] == "1080"
    assert spec.labels[paths.ROLE_LABEL] == "gateway"
    assert spec.labels[paths.EXIT_LABEL] == new_exit().id
    assert spec.publish == [] and "KF_EXPOSE_PORT" not in spec.env


def test_spec_joins_the_bridge_for_a_local_provider(new_exit):
    install_module()
    ex = new_exit(module="faketor", lease="de", port=9050)
    spec = gateway.gateway_spec(
        ex, "10.89.0.7", endpoint_port=9050, network=paths.PROVIDERS_NETWORK
    )
    assert spec.network == paths.PROVIDERS_NETWORK
    assert spec.env["KF_ENDPOINT_PORT"] == "9050"
    assert spec.labels[paths.MODULE_LABEL] == "faketor"
    assert spec.labels[paths.LEASE_LABEL] == "de"


def test_a_consumer_adds_its_own_labels(new_exit):
    # kiwi-fox keeps app=kiwi-fox and kiwi-fox.role=gateway on its gateways, which
    # is what kiwi-pentesting discovers today.
    spec = gateway.gateway_spec(
        new_exit(), "203.0.113.9", labels={"app": "kiwi-fox", "kiwi-fox.role": "gateway"}
    )
    args = podman.spec_args(spec)
    assert "app=kiwi-fox" in args and "kiwi-fox.role=gateway" in args
    assert f"{paths.ROLE_LABEL}=gateway" in args  # kiwi-proxy's own filter survives
    assert "app=kiwi-proxy" in podman.spec_args(gateway.gateway_spec(new_exit(), "1.2.3.4"))


def test_spec_does_not_grant_net_raw(new_exit):
    spec = gateway.gateway_spec(new_exit(), "203.0.113.9")
    assert spec.cap_add == ["NET_ADMIN", "NET_BIND_SERVICE"]


def test_an_exposed_exit_publishes_the_host_listener(new_exit):
    ex = new_exit(expose=Expose(bind="127.0.0.1", port=1081))
    spec = gateway.gateway_spec(ex, "203.0.113.9")
    assert spec.publish == ["127.0.0.1:1081:1081/tcp"]
    assert spec.env["KF_EXPOSE_PORT"] == str(gateway.EXPOSE_PORT)
    assert "KF_EXPOSE_CREDS_FILE" not in spec.env
    assert "--publish" in podman.spec_args(spec)
    assert spec.labels[paths.EXPOSE_LABEL] == "127.0.0.1:1081"


def test_an_exposed_exit_with_a_user_mounts_its_own_secret(new_exit):
    ex = new_exit(expose=Expose(bind="10.8.0.25", port=1090, username="me", has_password=True))
    spec = gateway.gateway_spec(ex, "203.0.113.9")
    assert spec.publish == ["10.8.0.25:1090:1081/tcp"]
    name = paths.expose_secret_name(ex.id)
    assert (name, f"/run/secrets/{name}") in spec.secrets
    assert spec.env["KF_EXPOSE_CREDS_FILE"] == f"/run/secrets/{name}"
    # the password is never in env
    assert not any("pw" in v for v in spec.env.values())


def test_ipv6_bind_is_bracketed(new_exit):
    spec = gateway.gateway_spec(new_exit(expose=Expose(bind="::1", port=1081)), "1.2.3.4")
    assert spec.publish == ["[::1]:1081:1081/tcp"]


def test_resolver_mode_mounts_its_config(new_exit, monkeypatch):
    monkeypatch.setattr(dns, "load_stamps", lambda: {"google": "sdns://x"})
    ex = new_exit()
    assert gateway.write_resolver_config(ex).exists()
    conf = gateway.write_resolv_conf(ex)
    assert conf.read_text().startswith("nameserver 127.0.0.2")
    spec = gateway.gateway_spec(ex, "203.0.113.9")
    assert any(dst == "/run/kf/dnscrypt-proxy.toml" for _src, dst, _o in spec.volumes)


# --------------------------------------------------------------- credentials
def test_isolation_provider_gets_a_stable_per_exit_token(new_exit):
    install_module()  # faketor: auth="isolation"
    ex = new_exit(module="faketor", lease="de", port=9050)
    user, password = gateway.credentials(ex, password=None)
    # the same token kiwi-fox minted, because kiwi-fox's exit id is the profile id
    assert user == f"kf-{ex.id[:16]}"
    assert password == ex.id


def test_plain_endpoint_credentials_are_whatever_the_user_gave(new_exit, fake):
    ex = new_exit()
    ex.endpoint.username = "u"
    gateway.write_credentials(ex, "topsecret")
    assert fake.secrets[paths.creds_secret_name(ex.id)] == "u\ntopsecret\n"


def test_expose_user_without_a_password_is_refused(new_exit, fake):
    ex = new_exit(expose=Expose(port=1081, username="me"))
    with pytest.raises(gateway.GatewayError, match="no password"):
        gateway.write_expose_credentials(ex)


# ------------------------------------------------------------------ lifecycle
def test_up_starts_a_gateway_and_measures_through_it(new_exit, fake):
    ex = remote(new_exit)
    gw = gateway.up(ex)
    assert fake.started == [paths.gateway_name(ex.id)]
    assert gw.name == paths.gateway_name(ex.id)
    assert gw.network == f"container:{gw.name}"
    assert gw.forwarder == "127.0.0.1:1080"
    assert gw.resolver is None  # remote DNS mode
    assert gw.info and gw.info.ip == "198.51.100.7"  # measured inside, the host was offline
    assert not gw.reused


def test_a_second_consumer_reuses_the_running_gateway(new_exit, fake):
    # A browser and a pentest tool on one identity share one namespace and one exit.
    ex = remote(new_exit)
    gateway.up(ex)
    fake.join("kf-br-x", paths.gateway_name(ex.id))
    again = gateway.up(ex)
    assert again.reused
    assert fake.started == [paths.gateway_name(ex.id)]
    assert "kf-br-x" in fake.containers  # nobody was kicked out


def test_changed_settings_replace_an_idle_gateway(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex)
    ex.endpoint.port = 2080
    gw = gateway.up(ex)
    assert not gw.reused
    assert fake.started == [gw.name, gw.name]


def test_changed_settings_never_pull_the_rug_from_a_member(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex)
    fake.join("kp-sqlmap", paths.gateway_name(ex.id))
    ex.endpoint.port = 2080
    with pytest.raises(gateway.GatewayError, match="in use"):
        gateway.up(ex)
    gw = gateway.up(ex, replace=True)
    assert "kp-sqlmap" not in fake.containers  # replacing removes who joined
    assert fake.containers[gw.name]["env"]["KF_ENDPOINT_PORT"] == "2080"


def test_replace_restarts_even_with_matching_settings(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex)
    gateway.up(ex, replace=True)
    assert len(fake.started) == 2


def test_stale_members_are_removed_before_the_gateway_is_replaced(new_exit, fake):
    # podman refuses to replace a container others joined, even stopped ones.
    ex = remote(new_exit)
    fake.join("kf-br-old", paths.gateway_name(ex.id), running=False)
    gateway.up(ex)
    assert "kf-br-old" not in fake.containers


def test_release_keeps_a_gateway_someone_still_uses(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex)
    name = paths.gateway_name(ex.id)
    fake.join("kf-br-x", name)
    fake.join("kp-tool", name)
    assert gateway.release(ex.id, ignore=("kf-br-x",)) is False  # the tool still runs
    assert name in fake.containers
    del fake.containers["kp-tool"]
    assert gateway.release(ex.id, ignore=("kf-br-x",)) is True
    assert name not in fake.containers
    assert paths.creds_secret_name(ex.id) not in fake.secrets


def test_a_held_exit_survives_release(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex, keep=True)  # `kiwi-proxy up`
    assert gateway.release(ex.id) is False
    gateway.down(ex.id)  # `kiwi-proxy down`
    assert not gateway.held(ex.id)
    assert paths.gateway_name(ex.id) not in fake.containers


def test_down_removes_members_first(new_exit, fake):
    ex = remote(new_exit)
    gateway.up(ex)
    fake.join("kf-br-x", paths.gateway_name(ex.id))
    gateway.down(ex.id)
    assert fake.removed[0] == "kf-br-x"


# ------------------------------------------------------------------ providers
def test_up_brings_the_provider_up_and_pins_its_address(new_exit, fake):
    install_module()
    ex = remote(new_exit, module="faketor", lease="de", port=9050)
    gw = gateway.up(ex, measure=False)
    prov = paths.provider_container_name("faketor", "de")
    assert fake.started == [prov, gw.name]
    spec = fake.containers[gw.name]["spec"]
    assert spec.network == paths.PROVIDERS_NETWORK
    assert spec.env["KF_ENDPOINT_IP"] == fake.provider_ip


def test_the_provider_stays_while_another_gateway_uses_it(new_exit, fake):
    install_module()
    a = remote(new_exit, module="faketor", lease="de", port=9050)
    b = a.model_copy(update={"id": "bbbbbbbb-0000-0000-0000-000000000000", "name": "b"})
    gateway.up(a, measure=False)
    gateway.up(b, measure=False)
    prov = paths.provider_container_name("faketor", "de")
    gateway.down(a.id)
    assert prov in fake.containers  # b still exits through it
    gateway.down(b.id)
    assert prov not in fake.containers


def test_reconcile_fails_closed_on_a_drifted_provider(new_exit, fake):
    install_module()
    ex = remote(new_exit, module="faketor", lease="de", port=9050)
    gw = gateway.up(ex, measure=False)
    assert gateway.reconcile() == []
    fake.provider_ip = "10.89.231.99"  # the provider came back elsewhere
    assert gateway.reconcile() == [gw.name]
    assert gw.name not in fake.containers


def test_reconcile_ignores_plain_endpoints(new_exit, fake):
    gateway.up(remote(new_exit))
    fake.provider_ip = "10.89.231.99"
    assert gateway.reconcile() == []


def test_reap_tears_down_only_what_nobody_uses(new_exit, fake):
    idle = remote(new_exit)
    used = idle.model_copy(update={"id": "cccccccc-0000-0000-0000-000000000000", "name": "used"})
    kept = idle.model_copy(update={"id": "dddddddd-0000-0000-0000-000000000000", "name": "kept"})
    shown = idle.model_copy(
        update={
            "id": "eeeeeeee-0000-0000-0000-000000000000",
            "name": "shown",
            "expose": Expose(port=1081),
        }
    )
    for ex in (idle, used, shown):
        gateway.up(ex)
    gateway.up(kept, keep=True)
    fake.join("kf-br-x", paths.gateway_name(used.id))
    assert gateway.reap() == [paths.gateway_name(idle.id)]


def test_running_lists_gateways_from_every_app(new_exit, fake):
    gateway.up(remote(new_exit), labels={"app": "kiwi-fox"})
    rows = gateway.running()
    assert rows and rows[0]["app"] == "kiwi-fox" and rows[0]["state"] == "running"


def test_dependents_parses_podman_inspect(monkeypatch):
    calls = []

    def run(args, **k):
        calls.append(args)
        if args[:2] == ["inspect", "gw"]:
            return subprocess.CompletedProcess(args, 0, stdout="abc123\n", stderr="")
        if args[0] == "ps":
            return subprocess.CompletedProcess(args, 0, stdout="abc123\nd1\nd2\n", stderr="")
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="/gw\tpasta\n/kf-br-x\tcontainer:abc123\n/tool\tcontainer:gw\n",
            stderr="",
        )

    monkeypatch.setattr(podman, "exists", lambda n: True)
    monkeypatch.setattr(podman, "_run", run)
    assert podman.dependents("gw") == ["kf-br-x", "tool"]


def test_providers_manage_only_installed_modules():
    assert providers.manages("faketor") is False
    install_module()
    assert providers.manages("faketor") is True


# ------------------------------------------------------------- Tor Browser
def test_inject_is_the_default_and_leaves_env_alone(new_exit):
    assert "KF_SOCKS_AUTH" not in gateway.gateway_spec(new_exit(), "1.2.3.4").env


def test_passthrough_reaches_the_forwarder(new_exit):
    spec = gateway.gateway_spec(new_exit(socks_auth="passthrough"), "1.2.3.4")
    assert spec.env["KF_SOCKS_AUTH"] == "passthrough"


def test_passthrough_on_tor_brings_its_token(new_exit, fake):
    install_module()  # faketor: auth="isolation"
    ex = remote(new_exit, module="faketor", lease="de", port=9050, socks_auth="passthrough")
    gateway.up(ex, measure=False)
    assert fake.secrets[paths.creds_secret_name(ex.id)].startswith(f"kf-{ex.id[:16]}\n")


def test_passthrough_without_a_token_is_refused_up_front(new_exit, fake):
    with pytest.raises(gateway.GatewayError, match="passthrough needs"):
        gateway.up(remote(new_exit, socks_auth="passthrough"))


def test_a_headless_up_reuses_a_gateway_a_consumer_labelled(new_exit, fake):
    # kiwi-fox brings the exit up with its labels; `kiwi-proxy up` of the same exit
    # (no labels) while the browser runs must reuse it, not call it "in use".
    ex = remote(new_exit)
    gateway.up(ex, labels={"app": "kiwi-fox", "kiwi-fox.profile": ex.id})
    fake.join("kf-br-x", paths.gateway_name(ex.id))
    again = gateway.up(ex, keep=True)
    assert again.reused and "kf-br-x" in fake.containers
    assert fake.containers[again.name]["labels"]["app"] == "kiwi-fox"


def test_down_without_podman_only_forgets_the_hold(new_exit, monkeypatch):
    monkeypatch.setattr(podman, "available", lambda: False)
    gateway.hold(new_exit().id)
    gateway.down(new_exit().id)  # must not try to run podman
    assert not gateway.held(new_exit().id)
