"""The leak suite probes a *live* gateway namespace; none of it can be faked.

    kiwi-proxy up work && make leak ARGS="--exit work"

Without --exit it picks the first running gateway, whichever app started it (a
kiwi-fox profile's gateway counts).
"""

import pytest

from kiwi_proxy import exits, gateway, paths, podman


def pytest_addoption(parser):
    parser.addoption("--exit", action="store", default=None, help="name of a running exit to probe")


@pytest.fixture(scope="session")
def running_gateway(pytestconfig) -> dict:
    if not podman.available():
        pytest.skip("podman unavailable")
    ref = pytestconfig.getoption("--exit")
    wanted = paths.gateway_name(exits.resolve_ref(ref).id) if ref else None
    for gw in gateway.running():
        if gw["state"] == "running" and (wanted is None or gw["name"] == wanted):
            return gw
    pytest.skip("no running gateway; start one with `kiwi-proxy up <name>`")


@pytest.fixture(scope="session")
def gateway_name(running_gateway) -> str:
    return running_gateway["name"]


def sh(container: str, script: str) -> str:
    return podman.exec_(container, ["sh", "-c", script]).stdout.strip()


def dig_status(container: str, name: str) -> str:
    out = sh(container, f"dig +time=10 @127.0.0.2 {name} 2>&1")
    for line in out.splitlines():
        if "status:" in line:
            return line.split("status:")[1].split(",")[0].strip()
    return "NO-RESPONSE"
