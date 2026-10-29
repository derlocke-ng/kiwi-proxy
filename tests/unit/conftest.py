import datetime as dt

import pytest

from kiwi_proxy.models import Endpoint, Exit


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    """No test reads or writes the real exit store, keyring or runtime dir."""
    for var in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(var, str(tmp_path / var.lower()))
    monkeypatch.setenv("KIWI_PROXY_SECRETS", "file")


def make_exit(module=None, lease=None, port=1080, **kw) -> Exit:
    return Exit(
        id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        name="work",
        created=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        endpoint=Endpoint(host="10.64.0.1", port=port, module=module, lease=lease),
        **kw,
    )


@pytest.fixture
def new_exit():
    """make_exit, for tests: new_exit(module="tor", lease="de", port=9050)."""
    return make_exit
