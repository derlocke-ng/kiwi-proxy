"""Construct the GUI's widgets and drive the forms.

Builds the real dialogs, so an exception during construction (a button that then
silently does nothing) fails `make test`. Skipped without a display; `xvfb-run make
test` gives it one.
"""

from __future__ import annotations

import pytest

# exc_type: a broken PyGObject (built for another Python) raises ImportError, not
# ModuleNotFoundError; skip on that too rather than fail collection.
gi = pytest.importorskip("gi", exc_type=ImportError)
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from kiwi_proxy import exits, secrets  # noqa: E402
from kiwi_proxy.models import Endpoint, Expose  # noqa: E402

pytestmark = pytest.mark.skipif(not Gtk.init_check(), reason="no display; GTK cannot initialise")


@pytest.fixture(scope="module", autouse=True)
def _adw():
    Adw.init()


def _editor(ex=None):
    from kiwi_proxy.ui.dialogs import ExitEditor

    return ExitEditor(ex, lambda e: None)


def test_new_exit_collects_a_plain_endpoint():
    ed = _editor()
    ed.name_row.set_text("se")
    ed.endpoint_row.set_text("socks5://u:pw@10.64.0.1:1080")
    form = ed.collect()
    assert form["name"] == "se"
    assert (form["endpoint"].host, form["endpoint"].username, form["password"]) == (
        "10.64.0.1",
        "u",
        "pw",
    )
    assert form["expose"] is None and form["socks_auth"] == "inject"


def test_host_port_fields_follow_the_switches():
    ed = _editor()
    assert not ed.port_row.get_visible()
    ed.expose_row.set_active(True)
    assert ed.port_row.get_visible() and not ed.user_row.get_visible()
    ed.bind_row.set_text("10.8.0.25")
    assert ed.open_row.get_visible(), "a reachable address must offer the open/password choice"
    ed.auth_row.set_active(True)
    assert ed.user_row.get_visible() and ed.password_row.get_visible()
    assert not ed.open_row.get_visible()


def test_a_reachable_port_needs_a_password_or_a_yes():
    ed = _editor()
    ed.name_row.set_text("lan")
    ed.endpoint_row.set_text("10.64.0.1:1080")
    ed.expose_row.set_active(True)
    ed.bind_row.set_text("0.0.0.0")
    with pytest.raises(ValueError, match="other machines"):
        ed.collect()
    ed.open_row.set_active(True)
    assert ed.collect()["expose"] == Expose(bind="0.0.0.0", port=ed.collect()["expose"].port)
    ed.open_row.set_active(False)
    ed.auth_row.set_active(True)
    ed.user_row.set_text("me")
    with pytest.raises(ValueError, match="password"):
        ed.collect()
    ed.password_row.set_text("hunter2")
    form = ed.collect()
    assert form["expose"].username == "me" and form["expose_password"] == "hunter2"


def test_the_next_free_host_port_is_offered():
    exits.create("a", Endpoint(host="h", port=1), expose=Expose(port=1081))
    ed = _editor()
    assert int(ed.port_row.get_value()) == 1082
    ed.name_row.set_text("b")
    ed.endpoint_row.set_text("h:1")
    ed.expose_row.set_active(True)
    ed.port_row.set_value(1081)
    with pytest.raises(ValueError, match="already a's"):
        ed.collect()


def test_editing_keeps_the_stored_passwords():
    ex = exits.create(
        "work",
        Endpoint(host="10.64.0.1", port=1080, username="u", has_password=True),
        password="pw",
        expose=Expose(port=1081, username="me", has_password=True),
        expose_password="hunter2",
    )
    ed = _editor(ex)
    assert ed.endpoint_row.get_text() == "socks5://u@10.64.0.1:1080"  # never the password
    assert ed.password_row.get_text() == ""
    form = ed.collect()  # nothing retyped
    assert form["endpoint"] is ex.endpoint and form["password"] is None
    assert form["expose_password"] is None
    assert secrets.lookup(ex.id) == "pw" and secrets.lookup(ex.id, kind="expose") == "hunter2"


def test_tor_browser_mode_is_selectable():
    ed = _editor()
    ed.name_row.set_text("tb")
    ed.endpoint_row.set_text("10.64.0.1:9050")
    ed.socks_row.set_selected(1)
    assert ed.collect()["socks_auth"] == "passthrough"


def test_a_bad_endpoint_is_said_not_raised():
    ed = _editor()
    ed.name_row.set_text("x")
    ed.endpoint_row.set_text("nonsense")
    ed._on_save()
    assert ed.status_label.get_visible() and "parse" in ed.status_label.get_text()


def test_the_config_dialog_asks_for_a_modules_settings():
    from test_module_settings import MODULE_SRC

    from kiwi_proxy import paths
    from kiwi_proxy.ui.dialogs import ModuleConfigDialog, ModulesDialog

    mdir = paths.module_dir("fakemyst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    ModulesDialog()  # a Configure… button beside Set up for a module with settings
    dialog = ModuleConfigDialog("fakemyst")
    assert set(dialog.rows) == {"keystore", "passphrase"}
    import pytest

    with pytest.raises(ValueError, match="Keystore"):
        dialog.collect()
    dialog._files["keystore"] = "/w.json"
    dialog.rows["passphrase"].set_text("pw")
    assert dialog.collect() == {"keystore": "/w.json", "passphrase": "pw"}


def _pump(until, timeout=5.0):
    import time

    from gi.repository import GLib

    ctx = GLib.MainContext.default()
    deadline = time.monotonic() + timeout
    while not until() and time.monotonic() < deadline:
        while ctx.pending():
            ctx.iteration(False)
        time.sleep(0.01)
    assert until(), "the editor never heard back from the module"


def test_the_country_row_is_a_list_the_module_fills():
    from test_module_settings import MODULE_SRC

    from kiwi_proxy import paths
    from kiwi_proxy.ui.dialogs import ANY_COUNTRY, ExitEditor, LeasePicker

    mdir = paths.module_dir("fakemyst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    ed = ExitEditor(None, lambda e: None)
    assert isinstance(ed.country_row, Adw.ComboRow)
    assert ed.country is None and ed.country_row.get_model().get_string(0) == ANY_COUNTRY
    ed.source_row.set_selected(1 + ed._modules.index("fakemyst"))
    _pump(lambda: ed.country_row.get_model().get_n_items() == 3)
    model = ed.country_row.get_model()
    assert [model.get_string(i) for i in range(3)] == [
        ANY_COUNTRY,
        "DE — Germany (1)",
        "SE — Sweden (1)",
    ]
    ed.country_row.set_selected(2)
    assert ed.country == "SE"
    assert ed.lease_row.get_title() == "Node"  # the module's word for a lease
    # The exit is chosen in the picker, for the country chosen, and lands on the row.
    picked = []
    picker = LeasePicker("fakemyst", ed.country, ed._lease, lambda i, x: picked.append((i, x)))
    _pump(lambda: len(picker.rows) == 1)
    assert picker.status.get_text().startswith("1 node to choose from in SE")
    assert picker.get_title() == "Fake Myst node in SE"
    assert picker.id_row.get_title().startswith("Node id, 0xse1 for example")
    picker._pick("0xse1")
    assert picked[0][0] == "0xse1" and picked[0][1].kind == "hosting"
    ed._set_lease(*picked[0])
    assert ed.lease_row.get_subtitle() == "0xse1 · Kista · hosting · Bahnhof"
    assert ed.lease_copy.get_visible()
    ed.name_row.set_text("north")
    form = ed.collect()
    assert form["endpoint"].module == "fakemyst"
    assert form["endpoint"].country == "se" and form["endpoint"].lease == "0xse1"


def test_editing_a_module_exit_keeps_its_country():
    from test_module_settings import MODULE_SRC

    from kiwi_proxy import paths
    from kiwi_proxy.ui.dialogs import ExitEditor

    mdir = paths.module_dir("fakemyst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    ex = exits.create("de", exits.module_endpoint("fakemyst", lease="0xde1", country="de"))
    ed = ExitEditor(ex, lambda e: None)
    _pump(lambda: ed.country_row.get_model().get_n_items() == 3)
    assert ed.country == "DE"
    assert ed._lease == "0xde1" and ed.lease_row.get_subtitle() == "0xde1"
    assert ed.collect()["endpoint"].country == "de" and ed.collect()["endpoint"].lease == "0xde1"


def test_the_picker_filters_by_kind_and_search_and_forces_an_id():
    from test_module_settings import MODULE_SRC

    from kiwi_proxy import paths
    from kiwi_proxy.ui.dialogs import LeasePicker

    mdir = paths.module_dir("fakemyst")
    mdir.mkdir(parents=True, exist_ok=True)
    (mdir / "provider.py").write_text(MODULE_SRC)
    picked = []
    picker = LeasePicker("fakemyst", None, "0xde1", lambda i, x: picked.append((i, x)))
    _pump(lambda: len(picker.rows) == 2)
    assert [r.lease_id for r in picker.rows] == ["0xse1", "0xde1"]  # best quality first
    assert picker.listbox.get_selected_row().lease_id == "0xde1"  # the current one
    assert picker.id_row.get_text() == "0xde1"  # shown in full, to read and copy
    buttons, child = [], picker.kinds.get_first_child()
    while child is not None:
        buttons.append(child)
        child = child.get_next_sibling()
    assert {b.get_label() for b in buttons} == {"All (2)", "hosting (1)", "residential (1)"}
    rows = {r.lease_id: r for r in picker.rows}
    picker.search.set_text("de1")  # a piece of an id
    assert picker._filter(rows["0xde1"]) and not picker._filter(rows["0xse1"])
    picker.search.set_text("bahnhof")  # an ISP
    assert picker._filter(rows["0xse1"]) and not picker._filter(rows["0xde1"])
    picker.search.set_text("")
    next(b for b in buttons if b.get_label().startswith("hosting")).set_active(True)
    assert picker._kind == "hosting"
    assert picker._filter(rows["0xse1"]) and not picker._filter(rows["0xde1"])
    assert picker._filter(picker.listbox.get_row_at_index(0))  # the module's own choice stays
    # Clicking a row shows its full id; typing another id means that one instead.
    picker.listbox.select_row(rows["0xse1"])
    assert picker.id_row.get_text() == "0xse1"
    picker.id_row.set_text("0xforced")
    assert picker.listbox.get_selected_row() is None
    picker._on_use()
    assert picked == [("0xforced", None)]
    # The details dialog names the node by the module's word and offers its id.
    from kiwi_proxy.ui.dialogs import provider_line

    ex = exits.create("de", exits.module_endpoint("fakemyst", lease="0xde1", country="de"))
    assert provider_line(ex, "node") == "fakemyst · node 0xde1 · country de"


def test_details_and_modules_build(monkeypatch):
    from kiwi_proxy.ui.dialogs import ExitDetails, ModulesDialog, proxy_url

    ex = exits.create(
        "work",
        Endpoint(host="h", port=1),
        expose=Expose(port=1081, username="me", has_password=True),
        expose_password="x",
    )
    assert proxy_url(ex) == "socks5h://me@127.0.0.1:1081"
    ExitDetails(ex)
    ModulesDialog()


def test_the_window_lists_exits():
    from kiwi_proxy.ui.window import Window

    exits.create("work", Endpoint(host="10.64.0.1", port=1080), expose=Expose(port=1081))
    exits.create("fox", Endpoint(host="10.64.0.2", port=1080), owner="kiwi-fox")
    win = Window(application=None)
    assert win.stack.get_visible_child_name() == "list"
    assert len(win._rows) == 2
    row = next(r for r in win._rows.values() if r.get_title() == "work")
    assert "host 127.0.0.1:1081" in row.get_subtitle()
    assert row.copy_button.get_visible()
    fox = next(r for r in win._rows.values() if r.get_title() == "fox")
    assert "from kiwi-fox" in fox.get_subtitle() and not fox.copy_button.get_visible()
    assert fox.toggle_button.get_label() == "Bring up"


def test_the_window_starts_empty():
    from kiwi_proxy.ui.window import Window

    assert Window(application=None).stack.get_visible_child_name() == "empty"


def test_blocklists_and_resolve_through_are_chosen_per_exit():
    ed = _editor()
    ed.name_row.set_text("x")
    ed.endpoint_row.set_text("10.64.0.1:1080")
    assert ed.collect()["dns"].blocklists == ["oisd-big"]  # the default, ticked
    # One row for where names resolve, standing in for mode + upstream; the default
    # is a named resolver (Google), as the CLI's default is.
    assert ed.collect()["dns"].mode == "resolver" and ed.collect()["dns"].upstream == "google"
    ed.list_rows["oisd-big"].set_active(False)
    ed.list_rows["oisd-nsfw"].set_active(True)
    assert ed.collect()["dns"].blocklists == ["oisd-nsfw"]
    ed.resolve_row.set_selected(0)  # the exit itself (remote): .onion, the exit's own DNS
    assert ed.collect()["dns"].mode == "remote"
    quad9 = next(i for i, (m, u, _l) in enumerate(ed._resolve) if u == "quad9")
    ed.resolve_row.set_selected(quad9)
    assert ed.collect()["dns"].mode == "resolver" and ed.collect()["dns"].upstream == "quad9"
    assert ed.collect()["dns"].blocklists == ["oisd-nsfw"]  # ad-block applies regardless


def test_editing_shows_the_exits_lists():
    from kiwi_proxy.models import DnsConfig

    ex = exits.create("x", Endpoint(host="h", port=1), dns=DnsConfig(blocklists=[]))
    ed = _editor(ex)
    assert not any(row.get_active() for row in ed.list_rows.values())
    assert ed.collect()["dns"].blocklists == []


def test_testing_a_plain_upstream(monkeypatch):
    import datetime as dt

    from gi.repository import GLib

    from kiwi_proxy import endpoint
    from kiwi_proxy.models import ExitInfo

    seen = {}

    def preflight(ep, password=None):
        seen["ep"], seen["pw"] = ep, password
        return ExitInfo(
            ip="198.51.100.7", country="SE", city="Stockholm", seen=dt.datetime.now(dt.UTC)
        )

    monkeypatch.setattr(endpoint, "preflight", preflight)
    ed = _editor()
    ed.endpoint_row.set_text("socks5://u:pw@10.64.0.1:1080")
    ed._on_test()
    ctx = GLib.MainContext.default()
    for _ in range(200):
        ctx.iteration(False)
        if "198.51.100.7" in ed.test_row.get_subtitle():
            break
        import time

        time.sleep(0.01)
    assert ed.test_row.get_subtitle() == "198.51.100.7 SE Stockholm"
    assert seen["pw"] == "pw" and seen["ep"].host == "10.64.0.1"


def test_duplicate_fills_a_new_exit_without_passwords():
    from kiwi_proxy.ui.dialogs import ExitEditor

    ex = exits.create(
        "se",
        Endpoint(host="10.64.0.1", port=1080, username="u", has_password=True),
        password="pw",
        expose=Expose(port=1081),
    )
    ed = ExitEditor(None, lambda e: None, template=ex)
    assert ed.ex is None and ed.name_row.get_text() == "se-2"
    assert int(ed.port_row.get_value()) == 1082
    assert ed.endpoint_row.get_text() == "socks5://u@10.64.0.1:1080"
    assert "not copied" in ed.status_label.get_text()
    form = ed.collect()
    assert form["password"] is None and form["endpoint"] is not ex.endpoint


def test_the_row_menu_has_duplicate():
    from kiwi_proxy.ui.window import Window

    win = Window(application=None)
    assert win.lookup_action("duplicate") is not None


def test_the_window_opens_large_and_remembers_its_size(monkeypatch):
    import json

    from kiwi_proxy import gateway, paths
    from kiwi_proxy.ui.window import DEFAULT_SIZE, Window

    monkeypatch.setattr(gateway, "running", lambda: [])  # no podman poll from the test windows
    win = Window(application=None)
    assert win.get_default_size() == DEFAULT_SIZE  # room for the picker (720×780)
    win.set_default_size(900, 700)
    win._on_close_request()
    saved = json.loads((paths.config_dir() / "window.json").read_text())
    assert (saved["width"], saved["height"], saved["maximized"]) == (900, 700, False)
    again = Window(application=None)
    assert again.get_default_size() == (900, 700)
    (paths.config_dir() / "window.json").write_text('{"width": 10, "height": 10}')
    assert Window(application=None).get_default_size() == (640, 480)  # never unusably small


# -------------------------------------------------------------- snapshots
@pytest.fixture
def snapshot_env(monkeypatch, tmp_path):
    """Fast gpg and a hermetic 'device' for the snapshot screens."""
    import contextlib
    import shutil
    import subprocess
    import tempfile

    from kiwi_proxy import gateway, snapshots
    from kiwi_proxy.snapshots import crypt
    from kiwi_proxy.snapshots.folder import Folder

    if crypt.missing_tools():
        pytest.skip("snapshots need gpg and zstd")
    home = tempfile.mkdtemp(prefix="kp-ui-gpg-")
    monkeypatch.setattr(crypt, "S2K_COUNT", 1024)
    monkeypatch.setattr(crypt, "_gpg_home", lambda: contextlib.nullcontext(home))
    monkeypatch.setattr(gateway, "running", lambda: [])
    monkeypatch.setattr(gateway, "is_up", lambda exit_id: False)
    snapshots._session.clear()
    Folder.forget_unlocked()

    def device(name):
        for var in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
            monkeypatch.setenv(var, str(tmp_path / name / var.lower()))
        snapshots._session.clear()
        Folder.forget_unlocked()

    yield device
    snapshots._session.clear()
    Folder.forget_unlocked()
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "all"], capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


PASSPHRASE = "correct horse battery staple"


def test_the_snapshots_page_before_and_after_setup(snapshot_env, tmp_path):
    from kiwi_proxy import snapshots
    from kiwi_proxy.ui.snapshots import SnapshotsPage

    snapshot_env("lime")
    page = SnapshotsPage("when you add or change an exit")
    assert page.folder_row.get_subtitle().startswith("not chosen yet")
    assert not page.when.get_sensitive() and not page.crypt.get_sensitive()

    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="lime")
    page.sync()
    assert page.folder_row.get_subtitle() == str(tmp_path / "shared")
    assert page.device_row.get_text() == "lime"
    assert page.lock_button.get_label() == "Lock this device"
    page.automatic_row.set_active(False)
    page.keep_row.set_value(7)
    s = snapshots.load_settings()
    assert s.automatic is False and s.keep == 7
    page.lock_button.emit("clicked")
    assert page.lock_button.get_label() == "Unlock…" and not snapshots.unlocked()


def test_the_window_offers_what_is_only_in_the_folder(snapshot_env, tmp_path):
    from kiwi_proxy import snapshots
    from kiwi_proxy.snapshots import items
    from kiwi_proxy.ui.window import Window

    snapshot_env("lime")
    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="lime")
    ex = exits.create("mullvad", Endpoint(host="10.64.0.1", port=1080))
    items.take_exit(ex)

    snapshot_env("titan")
    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="titan")
    win = Window(application=None)
    _pump(lambda: win.away_group.get_visible())
    assert win.stack.get_visible_child_name() == "list"
    assert not win.group.get_visible()  # no exits of its own yet
    row = win._away_rows[0]
    assert row.get_title() == "mullvad" and "from lime" in row.get_subtitle()
    assert not win.snap_banner.get_revealed()


def test_the_window_says_when_the_folder_is_newer_and_when_it_is_locked(snapshot_env, tmp_path):
    from kiwi_proxy import snapshots
    from kiwi_proxy.snapshots import items
    from kiwi_proxy.ui.window import Window

    snapshot_env("lime")
    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="lime")
    ex = exits.create("mullvad", Endpoint(host="10.64.0.1", port=1080))
    first = items.take_exit(ex)

    snapshot_env("titan")
    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="titan")
    items.restore_exit(ex.id, first.id)
    restored = exits.load(ex.id)
    restored.notes = "changed on titan"
    exits.save(restored)
    items.take_exit(restored)

    snapshot_env("lime")
    win = Window(application=None)
    _pump(lambda: win._relations.get(ex.id) is not None)
    assert "newer snapshot from titan" in win._rows[ex.id].get_subtitle()

    snapshots.lock()
    win._poll_snapshots()
    _pump(lambda: win.snap_banner.get_revealed())


def test_the_history_dialog_lists_and_takes(snapshot_env, tmp_path):
    from kiwi_proxy import snapshots
    from kiwi_proxy.snapshots import items
    from kiwi_proxy.ui.snapshots import HistoryDialog

    snapshot_env("lime")
    snapshots.setup(tmp_path / "shared", PASSPHRASE, device_name="lime")
    ex = exits.create("mullvad", Endpoint(host="10.64.0.1", port=1080))
    items.take_exit(ex)
    dialog = HistoryDialog(
        "exit", ex.id, ex.name, here=True,
        take=lambda: items.take_exit(exits.load(ex.id)),
        restore=lambda sid: items.restore_exit(ex.id, sid),
    )  # fmt: skip
    _pump(lambda: len(dialog.rows) == 1)
    assert "lime" in dialog.rows[0].get_subtitle()
    dialog.take_button.emit("clicked")
    _pump(lambda: len(dialog.rows) == 2)
    assert "1 of" not in dialog.status.get_label() and "2 of 5 kept" in dialog.status.get_label()
