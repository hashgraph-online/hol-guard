"""Facades must not hide raw egress or turn managed bindings into raw clients."""

from pathlib import Path

from tests.http_client_inventory_support import HttpClientInventory
from tests.test_guard_mdm_http_inventory import _RAW_HTTP_BOUNDARIES, _RAW_HTTP_CALLS


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_imported_facade_and_assigned_function_cannot_hide_raw_egress(tmp_path: Path) -> None:
    _write(tmp_path, "daemon/transport.py", "from urllib.request import urlopen as send\n")
    _write(tmp_path, "daemon/manager.py", "from . import transport as owner\nraw_send = owner.send\n")
    path = _write(
        tmp_path,
        "runtime/escape.py",
        "from ..daemon import manager as lifecycle\nsend = lifecycle.raw_send\nsend('https://fixture.invalid')\n",
    )

    calls = HttpClientInventory(tmp_path).calls(path)

    assert calls == [(3, "urllib.request.urlopen")]
    assert path.relative_to(tmp_path).as_posix() not in _RAW_HTTP_BOUNDARIES
    assert calls[0][1] in _RAW_HTTP_CALLS


def test_original_module_alias_resolves_each_moved_loopback_call(tmp_path: Path) -> None:
    _write(tmp_path, "daemon/manager.py", "import urllib.error\nimport urllib.request\n")
    path = _write(
        tmp_path,
        "daemon/manager_live.py",
        "from . import manager as _manager\n_manager.urllib.request.urlopen('http://127.0.0.1')\n",
    )

    assert HttpClientInventory(tmp_path).calls(path) == [(2, "urllib.request.urlopen")]


def test_facade_name_does_not_substitute_for_the_actual_export_binding(tmp_path: Path) -> None:
    _write(tmp_path, "daemon/manager.py", "import urllib.request\nurllib = object()\n")
    path = _write(
        tmp_path,
        "daemon/manager_live.py",
        "from . import manager as _manager\n_manager.urllib.request.urlopen('http://127.0.0.1')\n",
    )

    calls = HttpClientInventory(tmp_path).calls(path)

    assert calls == [(2, "codex_plugin_scanner.guard.daemon.manager.urllib.request.urlopen")]
    assert calls[0][1] not in _RAW_HTTP_CALLS


def test_managed_transport_alias_does_not_become_a_raw_http_client(tmp_path: Path) -> None:
    _write(tmp_path, "mdm/network.py", "def managed_urlopen(request):\n    pass\n")
    _write(tmp_path, "daemon/manager.py", "from ..mdm.network import managed_urlopen as send\n")
    path = _write(
        tmp_path,
        "runtime/managed.py",
        "from ..daemon.manager import send\nsend('https://fixture.invalid')\n",
    )

    calls = HttpClientInventory(tmp_path).calls(path)

    assert calls == [(2, "codex_plugin_scanner.guard.mdm.network.managed_urlopen")]
    assert calls[0][1] not in _RAW_HTTP_CALLS


def test_cyclic_facade_exports_are_bounded_and_do_not_invent_a_raw_binding(tmp_path: Path) -> None:
    _write(tmp_path, "daemon/a.py", "from .b import send\n")
    _write(tmp_path, "daemon/b.py", "from .a import send\n")
    path = _write(tmp_path, "runtime/alias.py", "from ..daemon.a import send\nsend('fixture')\n")

    calls = HttpClientInventory(tmp_path).calls(path)

    assert len(calls) == 1
    assert calls[0][1] not in _RAW_HTTP_CALLS
