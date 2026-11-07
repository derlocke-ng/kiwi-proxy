"""podman: the few behaviours kiwi-proxy relies on, without a podman."""

from __future__ import annotations


def test_logs_merge_stderr_and_drop_colours(monkeypatch):
    """A daemon logs to stderr, in colour; an error quoting its last lines wants
    both streams in order and plain text — and nothing for a container that is gone."""
    import subprocess

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
