"""Thin wrapper over the podman CLI. Argument lists only, never shell=True."""

from __future__ import annotations

import json
import shutil
import subprocess
import time

from . import paths
from .models import ContainerSpec


class PodmanError(RuntimeError):
    pass


def available() -> bool:
    return shutil.which("podman") is not None


def _run(args: list[str], *, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    proc = subprocess.run(  # noqa: S603
        ["podman", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and proc.returncode != 0:
        raise PodmanError(f"podman {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc


def version() -> str:
    return _run(["--version"]).stdout.strip()


def ps(all_: bool = True, *, labels: dict[str, str] | None = None) -> list[dict]:
    """kiwi-proxy's containers, whichever app asked for them; `labels` narrows it."""
    args = ["ps", "--format", "json", "--filter", paths.FILTER]
    for key, val in sorted((labels or {}).items()):
        args += ["--filter", f"label={key}={val}"]
    if all_:
        args.append("--all")
    out = _run(args).stdout.strip()
    return json.loads(out) if out else []


def exists(name: str) -> bool:
    # Listing exits must work on a machine without podman: nothing is up there.
    if not available():
        return False
    return _run(["container", "exists", name], check=False).returncode == 0


def is_running(name: str) -> bool:
    if not exists(name):
        return False
    state = _run(["inspect", name, "--format", "{{.State.Running}}"], check=False).stdout.strip()
    return state == "true"


def rm(name: str, *, force: bool = True, wait: float = 5.0) -> None:
    """Remove and wait for it to actually be gone.

    `podman rm` returning is not the same as the name being free, and callers that
    immediately recreate the container hit "name is already in use".
    """
    if not exists(name):
        return
    # Stop politely first. `rm --force` SIGKILLs the container, and a hard-killed
    # Firefox leaves a stale lock in the profile directory that breaks the *next*
    # start — which looked like random "tab crashes" and made probing unrepeatable.
    if is_running(name):
        _run(["stop", "--time", "8", name], check=False, timeout=30)
    _run(["rm", *(["--force"] if force else []), name], check=False)
    deadline = time.monotonic() + wait
    while exists(name) and time.monotonic() < deadline:
        time.sleep(0.1)


def logs(name: str, tail: int = 50) -> str:
    return _run(["logs", "--tail", str(tail), name], check=False).stdout


def exec_(name: str, args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    return _run(["exec", name, *args], check=False, timeout=timeout)


def spec_args(spec: ContainerSpec, *, detach: bool = True) -> list[str]:
    """Rendered separately from running it, so specs can be golden-file tested."""
    # --replace rather than a separate rm: `podman rm` can return before the
    # storage entry is released, and starting several profiles in quick succession
    # then fails with "container name is already in use". Replacing is atomic.
    args = ["run", "--replace", "--name", spec.name]
    if detach:
        args.append("--detach")
    args += ["--network", spec.network]
    if spec.ip:
        args += ["--ip", spec.ip]
    if spec.restart:
        args += ["--restart", spec.restart]
    if spec.userns:
        args += ["--userns", spec.userns]
    for cap in spec.cap_drop:
        args += ["--cap-drop", cap]
    for cap in spec.cap_add:
        args += ["--cap-add", cap]
    for opt in spec.security_opt:
        args += ["--security-opt", opt]
    for key, val in sorted(spec.env.items()):
        args += ["--env", f"{key}={val}"]
    for src, dst, opts in spec.volumes:
        args += ["--volume", f"{src}:{dst}:{opts}"]
    for path in spec.tmpfs:
        args += ["--tmpfs", path]
    for dev in spec.devices:
        args += ["--device", dev]
    for port in spec.publish:
        args += ["--publish", port]
    for name, target in spec.secrets:
        # A secret, not a bind mount: the gateway runs as container-root (a
        # subuid), so a 0600 file owned by the host user is correctly unreadable.
        args += ["--secret", f"{name},type=mount,target={target}"]
    # "app" names the application the container is for. A consumer may set it
    # (kiwi-fox labels its gateways app=kiwi-fox, which kiwi-pentesting discovers);
    # kiwi-proxy's own filter is the kiwi-proxy.role label, not this.
    for key, val in sorted({"app": paths.APP, **spec.labels}.items()):
        args += ["--label", f"{key}={val}"]
    args.append(spec.image)
    args += spec.args
    return args


def start(spec: ContainerSpec, *, detach: bool = True) -> str:
    return _run(spec_args(spec, detach=detach), timeout=180).stdout.strip()


def wait(name: str, timeout: int | None = None) -> int:
    """Block until the container exits; returns its exit code."""
    proc = _run(["wait", name], check=False, timeout=timeout or 86400)
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return -1


def secret_set(name: str, value: str) -> None:
    proc = subprocess.run(  # noqa: S603
        ["podman", "secret", "create", "--replace", name, "-"],
        input=value,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise PodmanError(f"could not store secret {name}: {proc.stderr.strip()}")


def secret_rm(name: str) -> None:
    _run(["secret", "rm", name], check=False)


def orphans() -> list[str]:
    return [c["Names"][0] for c in ps() if c.get("Names")]


def labels(name: str) -> dict[str, str]:
    if not exists(name):
        return {}
    out = _run(["inspect", name, "--format", "{{json .Config.Labels}}"], check=False).stdout
    try:
        found = json.loads(out or "{}")
    except json.JSONDecodeError:
        return {}
    return found if isinstance(found, dict) else {}


def dependents(name: str) -> list[str]:
    """Containers that joined `name`'s network namespace (--network container:).

    podman refuses to replace or remove a container that others depend on, so a
    gateway being replaced has to know who is inside it: a browser, a pentest tool,
    a microsocks adapter."""
    if not exists(name):
        return []
    ident = _run(["inspect", name, "--format", "{{.Id}}"], check=False).stdout.strip()
    ids = _run(["ps", "--all", "--quiet", "--no-trunc"], check=False).stdout.split()
    if not ids:
        return []
    fmt = "{{.Name}}\t{{.HostConfig.NetworkMode}}"
    out = _run(["inspect", "--format", fmt, *ids], check=False).stdout
    wanted = {f"container:{name}", f"container:{ident}"} if ident else {f"container:{name}"}
    found = []
    for line in out.splitlines():
        cname, _, mode = line.partition("\t")
        if mode.strip() in wanted:
            found.append(cname.strip().lstrip("/"))
    return found


# ---------------------------------------------------------------- networks
# Local provider containers (tor, vpn, 9proxy, mysterium) need their own exit to
# the internet AND to be reachable by the gateway that forwards into them. They
# cannot share the gateway's netns — the gateway default-drops everything but one
# destination, which would strand the provider's own upstream — so they meet on a
# user-defined bridge instead, and the gateway permits exactly the provider's
# address on it.


def network_exists(name: str) -> bool:
    return _run(["network", "exists", name], check=False).returncode == 0


def network_ensure(name: str, *, subnet: str | None = None, gateway: str | None = None) -> None:
    """Idempotent `podman network create`. A rootless bridge gives attached
    containers outbound connectivity and lets them reach each other by IP.

    A fixed subnet lets kiwi-proxy assign providers deterministic static addresses,
    so a gateway's firewall pin stays valid across a provider restart and a freed
    address cannot be reused by a different container."""
    if network_exists(name):
        return
    # `--ignore` makes a concurrent create a no-op rather than an error.
    args = ["network", "create", "--ignore"]
    if subnet:
        args += ["--subnet", subnet]
    if gateway:
        args += ["--gateway", gateway]
    args.append(name)
    _run(args)


def network_rm(name: str) -> None:
    _run(["network", "rm", name], check=False)


def container_ip(name: str, network: str) -> str | None:
    """The container's IPv4 address on a specific network, or None if it is not
    running or not attached there yet. The gateway's firewall needs a literal
    address, so this is how a provider's bridge IP is resolved on the host."""
    if not is_running(name):
        return None
    fmt = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
    out = _run(["inspect", name, "--format", fmt], check=False).stdout.strip()
    return out or None


def container_env(name: str, key: str) -> str | None:
    """Read one environment variable a container was started with."""
    if not exists(name):
        return None
    fmt = "{{range .Config.Env}}{{println .}}{{end}}"
    out = _run(["inspect", name, "--format", fmt], check=False).stdout
    prefix = f"{key}="
    for line in out.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return None


def image_exists(image: str) -> bool:
    return _run(["image", "exists", image], check=False).returncode == 0


def pull(image: str) -> None:
    _run(["pull", image], timeout=600)


def build(
    image: str, containerfile: str, context: str, *, labels: dict[str, str] | None = None
) -> None:
    args = ["build", "-t", image, "-f", containerfile]
    for key, val in sorted((labels or {}).items()):
        args += ["--label", f"{key}={val}"]
    args.append(context)
    _run(args, timeout=1800)
