"""Coverage for the stdlib-only ``_record_extraction_owner`` entry twin.

The function lives in the PyInstaller entrypoint where importing the Guard
package is off-limits, so it is loaded from ``scripts/mdm`` directly.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import types
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import onefile_extraction

_ENTRY_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mdm" / "hol-guard-entry.py"


def _load_entry() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("hol_guard_entry_for_test", _ENTRY_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def entry() -> types.ModuleType:
    return _load_entry()


def _meipass(tmp_path: Path, name: str = "_MEIabc123") -> Path:
    directory = tmp_path / name
    directory.mkdir(parents=True)
    return directory


def _marker(directory: Path) -> Path:
    return directory / ".hol-guard-extraction-owner.json"


def test_record_extraction_owner_writes_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: types.ModuleType
) -> None:
    extraction = _meipass(tmp_path)
    (extraction / "version.py").write_text('__version__ = "9.9.9-test"\n', encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(extraction), raising=False)
    monkeypatch.setattr(entry.tempfile, "gettempdir", lambda: str(tmp_path))

    entry._record_extraction_owner()

    marker = _marker(extraction)
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema"] == "guard.onefile-extraction-owner.v1"
    assert payload["pid"] == os.getpid()
    assert payload["parent_pid"] == os.getppid()
    assert payload["guard_version"] == "9.9.9-test"
    assert isinstance(payload["started_at"], str)
    if os.name != "nt":
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert str(tmp_path) not in marker.read_text(encoding="utf-8")


def test_record_extraction_owner_skip_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: types.ModuleType
) -> None:
    monkeypatch.setattr(entry.tempfile, "gettempdir", lambda: str(tmp_path))

    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    entry._record_extraction_owner()
    assert not list(tmp_path.rglob("*.hol-guard-extraction-owner.json"))

    named_otherwise = _meipass(tmp_path, "hol-guard-bundle")
    monkeypatch.setattr(sys, "_MEIPASS", str(named_otherwise), raising=False)
    entry._record_extraction_owner()
    assert not _marker(named_otherwise).exists()

    nested_root = tmp_path / "elsewhere"
    nested = _meipass(nested_root)
    monkeypatch.setattr(sys, "_MEIPASS", str(nested), raising=False)
    entry._record_extraction_owner()
    assert not _marker(nested).exists()

    not_a_dir = tmp_path / "_MEIfile000"
    not_a_dir.write_text("x", encoding="utf-8")
    monkeypatch.setattr(sys, "_MEIPASS", str(not_a_dir), raising=False)
    entry._record_extraction_owner()
    assert not _marker(not_a_dir).exists()

    if os.name != "nt":
        real = _meipass(tmp_path, "real-target")
        link = tmp_path / "_MEIlink99"
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            pass
        else:
            monkeypatch.setattr(sys, "_MEIPASS", str(link), raising=False)
            entry._record_extraction_owner()
            assert not _marker(real).exists()


def test_record_extraction_owner_never_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: types.ModuleType
) -> None:
    extraction = _meipass(tmp_path)
    monkeypatch.setattr(sys, "_MEIPASS", str(extraction), raising=False)
    monkeypatch.setattr(entry.tempfile, "gettempdir", lambda: str(tmp_path))

    def boom() -> str:
        raise RuntimeError("version unavailable")

    monkeypatch.setattr(entry, "_packaged_version", boom)
    entry._record_extraction_owner()
    payload = json.loads(_marker(extraction).read_text(encoding="utf-8"))
    assert payload["guard_version"] == "unknown"

    monkeypatch.delattr(entry, "_packaged_version")
    monkeypatch.setattr(
        entry.os,
        "replace",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("rename failed")),
    )
    extraction2 = _meipass(tmp_path, "_MEIother00")
    monkeypatch.setattr(sys, "_MEIPASS", str(extraction2), raising=False)
    entry._record_extraction_owner()
    assert not _marker(extraction2).exists()


def test_entry_records_owner_before_bridge_and_guard_imports() -> None:
    source = _ENTRY_SCRIPT.read_text(encoding="utf-8")
    main = source[source.index('if __name__ == "__main__":') :]
    bootstrap = main.index("_try_proxy_running_desktop_bootstrap()")
    record = main.index("_record_extraction_owner()\n")
    bridge = main.index("_try_codex_daemon_bridge()")
    heavy = main.index("from codex_plugin_scanner.guard.frozen_daemon_runtime import")
    assert bootstrap < record < bridge < heavy


def test_entry_marker_literals_match_module_constants() -> None:
    """The stdlib-only entry twin must write the same marker as the module."""

    source = _ENTRY_SCRIPT.read_text(encoding="utf-8")
    assert f'"{onefile_extraction.OWNER_MARKER_NAME}"' in source
    assert f'"{onefile_extraction._OWNER_MARKER_SCHEMA}"' in source  # pyright: ignore[reportPrivateUsage]
