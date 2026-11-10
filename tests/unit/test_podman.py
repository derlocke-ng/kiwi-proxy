"""podman: the few behaviours kiwi-proxy relies on, without a podman."""

from __future__ import annotations

import subprocess

import pytest

from kiwi_proxy import podman


def test_logs_merge_stderr_and_drop_colours(monkeypatch):
    """A daemon logs to stderr, in colour; an error quoting its last lines wants
    both streams in order and plain text — and nothing for a container that is gone."""

    from kiwi_proxy import podman

    calls = []

    def fake_run(args, **kw):
        calls.append((args, kw))
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="kf-x: starting\n\x1b[90m02:28\x1b[0m \x1b[31mERR\x1b[0m boom\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert podman.logs("c1", tail=3) == "kf-x: starting\n02:28 ERR boom\n"
    args, kw = calls[0]
    assert args == ["podman", "logs", "--tail", "3", "c1"]
    assert kw["stderr"] is subprocess.STDOUT and kw["stdout"] is subprocess.PIPE
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda a, **k: subprocess.CompletedProcess(a, 125, stdout="Error: no such container\n"),
    )
    assert podman.logs("gone") == ""


def test_a_tun_device_runs_the_container_unlabelled():
    """SELinux refuses /dev/net/tun to the container type; a tunnel that is given
    the device needs labelling off, and only then — a label the spec sets wins."""
    from kiwi_proxy import podman
    from kiwi_proxy.models import ContainerSpec

    plain = podman.spec_args(ContainerSpec(name="c", image="i", network="pasta"))
    assert "label=disable" not in plain and "--security-opt" in plain  # no-new-privileges stays
    tun = podman.spec_args(
        ContainerSpec(name="c", image="i", network="pasta", devices=["/dev/net/tun"])
    )
    assert (
        tun.count("--security-opt") == 2 and "label=disable" in tun and "no-new-privileges" in tun
    )
    assert tun.index("--device") > tun.index("label=disable")
    own = podman.spec_args(
        ContainerSpec(
            name="c",
            image="i",
            network="pasta",
            devices=["/dev/net/tun"],
            security_opt=["no-new-privileges", "label=type:spc_t"],
        )
    )
    assert "label=disable" not in own and "label=type:spc_t" in own


def test_dependents_refuses_a_failed_listing(monkeypatch):
    def run(args, *, check=True, timeout=120):
        if args[0] == "ps":
            if check:
                raise podman.PodmanError("podman ps failed: timed out")
            return subprocess.CompletedProcess(args, 125, stdout="", stderr="timed out")
        return subprocess.CompletedProcess(args, 0, stdout="abc\n", stderr="")

    monkeypatch.setattr(podman, "exists", lambda n: True)
    monkeypatch.setattr(podman, "_run", run)
    with pytest.raises(podman.PodmanError):
        podman.dependents("gw")


def test_commit_does_not_pause_and_checks_the_image_is_there(monkeypatch):
    calls = []

    def run(args, *, check=True, timeout=120):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(podman, "_run", run)
    podman.commit("kc-box-1", "localhost/kc/box-1:latest")
    assert calls[0] == ["commit", "-q", "--pause=false", "kc-box-1", "localhost/kc/box-1:latest"]
    assert calls[1] == ["image", "exists", "localhost/kc/box-1:latest"]

    def gone(args, *, check=True, timeout=120):
        rc = 1 if args[:2] == ["image", "exists"] else 0
        return subprocess.CompletedProcess(args, rc, stdout="", stderr="")

    monkeypatch.setattr(podman, "_run", gone)
    with pytest.raises(podman.PodmanError, match="not there"):
        podman.commit("kc-box-1", "localhost/kc/box-1:latest")


def test_a_secret_is_read_back_exactly(monkeypatch):
    """podman 5's real output shape for `secret inspect --showsecret` (no --format:
    `--format json` prints the word "json")."""
    calls = []

    def run(args, *, check=True, timeout=120):
        calls.append(args)
        out = (
            '[{"ID": "abc", "CreatedAt": "2026-11-10T17:00:00Z", "Spec": {"Name": "kf-mod-x-p"},'
            ' "SecretData": "probe-456\\n"}]'
        )
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(podman, "_run", run)
    assert podman.secret_value("kf-mod-x-p") == "probe-456\n"
    assert "--format" not in calls[0]
