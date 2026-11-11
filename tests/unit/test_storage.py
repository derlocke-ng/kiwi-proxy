"""Podman's storage: leftovers per app, the quick check with names, the repair."""

from __future__ import annotations

import json
import subprocess
import time

import pytest

from kiwi_proxy import paths, podman, storage

OLD = time.time() - 3600
LAYER = "d6aad1833cb0ef30e107b076dc1ebbecac91591d815b881379bcce44ef3fe33a"
DAMAGED = (
    f"Damaged layer {LAYER}:\n1 error occurred:\n\t* layer {LAYER}: faccessat "
    f"/x/overlay/{LAYER}: no such file or directory\n\nError: damage detected in local storage\n"
)


class FakePodman:
    def __init__(self, monkeypatch, rows, *, broken=(), check_output=""):
        self.rows = rows
        self.broken = set(broken)
        self.check_output = check_output
        self.calls: list[list[str]] = []
        monkeypatch.setattr(podman, "available", lambda: True)
        monkeypatch.setattr(podman, "_run", self.run)

    def run(self, args, *, check=True, timeout=120):
        self.calls.append(args)
        if args[:2] == ["ps", "--all"]:
            return subprocess.CompletedProcess(args, 0, json.dumps(self.rows), "")
        if args[:2] == ["system", "check"]:
            if "--repair" in args:
                # without --force podman leaves a layer a container still uses
                if not self.broken:
                    self.check_output = ""
                return subprocess.CompletedProcess(args, 0, "", "")
            if self.check_output:
                return subprocess.CompletedProcess(args, 125, "", self.check_output)
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["container", "inspect"]:
            ident = args[-1]
            if ident in self.broken:
                return subprocess.CompletedProcess(
                    args,
                    125,
                    "",
                    f'Error: getting graph driver info "{ident}": no such file or directory',
                )
            return subprocess.CompletedProcess(args, 0, "overlay\n", "")
        if args[:2] == ["rm", "--force"]:
            ident = args[-1]
            self.rows = [r for r in self.rows if ident not in (r["Id"], r["Names"][0])]
            self.broken.discard(ident)
            if not self.broken:
                self.check_output = ""
            return subprocess.CompletedProcess(args, 0, ident, "")
        return subprocess.CompletedProcess(args, 0, "", "")


def row(ident, name, state, labels, created=OLD):
    return {"Id": ident, "Names": [name], "State": state, "Labels": labels, "Created": created}


ROWS = [
    row("a1", "kf-gw-1", "exited", {paths.ROLE_LABEL: "gateway"}),
    row("a2", "kf-gw-2", "running", {paths.ROLE_LABEL: "gateway"}),
    row("a3", "kf-gw-3", "created", {paths.ROLE_LABEL: "gateway"}, created=time.time()),
    row("b1", "kf-br-1", "created", {"app": "kiwi-fox", "kiwi-fox.profile": "x"}),
    row("c1", "kc-box-1", "exited", {"app": "kiwi-custodia", "kiwi-custodia.role": "box"}),
    row("d1", "my-postgres", "exited", {}),
]


def test_leftovers_are_per_app_and_spare_what_is_starting(monkeypatch):
    FakePodman(monkeypatch, ROWS)
    assert [c.name for c in storage.leftovers("kiwi-proxy")] == ["kf-gw-1"]
    assert [c.name for c in storage.leftovers("kiwi-fox")] == ["kf-br-1"]
    assert [c.name for c in storage.leftovers("kiwi-custodia")] == ["kc-box-1"]
    # never someone else's
    assert all(
        c.name != "my-postgres"
        for app in ("kiwi-proxy", "kiwi-fox")
        for c in storage.leftovers(app)
    )


def test_a_clean_store_is_fine(monkeypatch):
    FakePodman(monkeypatch, ROWS)
    report = storage.check()
    assert report.ok and not report.broken


def test_damage_is_named_by_container_and_owner(monkeypatch):
    FakePodman(monkeypatch, ROWS, broken={"c1", "d1"}, check_output=DAMAGED)
    report = storage.check()
    assert not report.ok and report.layers == [LAYER]
    assert [c.name for c in report.ours] == ["kc-box-1"]
    assert [c.name for c in report.others] == ["my-postgres"]


def test_repair_removes_only_what_it_is_told(monkeypatch):
    fake = FakePodman(monkeypatch, ROWS, broken={"c1", "d1"}, check_output=DAMAGED)
    report = storage.check()
    after = storage.repair(report, [c.id for c in report.ours])
    removed = [a[-1] for a in fake.calls if a[:2] == ["rm", "--force"]]
    assert removed == ["c1"]
    assert not after.ok and [c.name for c in after.others] == ["my-postgres"]
    after = storage.repair(after, [c.id for c in after.others])
    assert after.ok


@pytest.mark.parametrize(
    ("labels", "app"),
    [
        ({paths.ROLE_LABEL: "provider"}, "kiwi-proxy"),
        ({"app": "kiwi-fox"}, "kiwi-fox"),
        ({"kiwi-custodia.role": "tunnel"}, "kiwi-custodia"),
        ({"app": "nextcloud"}, None),
        ({}, None),
    ],
)
def test_owner(labels, app):
    assert storage.Container("i", "n", "exited", labels).app == app


# ------------------------------------------------- new exits (the DNS page)
def test_a_new_exit_starts_with_the_dns_preferences():
    from kiwi_proxy import exits, prefs
    from kiwi_proxy.models import Endpoint

    plain = exits.create("plain", Endpoint(host="10.64.0.1", port=1080))
    assert plain.dns.upstream == "google" and plain.dns.blocklists == ["oisd-big"]
    prefs.save(prefs.Prefs(new_exit_upstream="quad9", new_exit_blocklists=[]))
    ex = exits.create("q9", Endpoint(host="10.64.0.2", port=1080))
    assert ex.dns.mode == "resolver" and ex.dns.upstream == "quad9" and ex.dns.blocklists == []
    # what the file says is checked: an unknown upstream or list falls back
    prefs.path().write_text(
        '{"new_exit_upstream": "nope", "new_exit_blocklists": ["x", "oisd-small"]}'
    )
    assert prefs.new_exit_dns().upstream == "google"
    assert prefs.new_exit_dns().blocklists == ["oisd-small"]
