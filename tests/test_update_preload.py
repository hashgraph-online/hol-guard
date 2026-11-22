"""`hol-guard update` stays on one release while the installer replaces it."""

from __future__ import annotations

import argparse
import importlib
import io
import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.cli.update_preload import emit_update_result, load_package_before_install

OLD_RELEASE = {
    "__init__.py": "",
    "output.py": "def old_link():\n    return 'old'\n",
    "render.py": "from .output import old_link\n\ndef emit():\n    return old_link()\n",
    "optional.py": "import a_dependency_this_machine_does_not_have\n",
}
NEW_RELEASE = {
    "output.py": "def new_link():\n    return 'new'\n",
    "render.py": "from .output import new_link\n\ndef emit():\n    return new_link()\n",
}


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")


@pytest.fixture
def release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A package whose files a later release replaces in place, as the installer does."""
    name = f"guard_release_{tmp_path.name.replace('-', '_')}"
    root = tmp_path / name
    root.mkdir()
    _write(root, OLD_RELEASE)
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name, root
    for module in [key for key in sys.modules if key == name or key.startswith(f"{name}.")]:
        del sys.modules[module]


def _install_new_release(root: Path) -> None:
    _write(root, NEW_RELEASE)
    for cache in root.glob("__pycache__/*"):
        cache.unlink()
    importlib.invalidate_caches()


def test_a_module_first_imported_after_the_install_breaks_without_the_preload(release) -> None:
    name, root = release
    importlib.import_module(f"{name}.output")
    _install_new_release(root)
    with pytest.raises(ImportError):
        importlib.import_module(f"{name}.render")


def test_the_preload_keeps_the_run_on_the_release_that_started_it(release) -> None:
    name, root = release
    assert load_package_before_install(name) == 1  # the optional module
    _install_new_release(root)
    assert importlib.import_module(f"{name}.render").emit() == "old"


def test_a_missing_package_counts_as_one_failure() -> None:
    assert load_package_before_install("guard_release_that_is_not_installed") == 1


def _broken_emit(_command: str, _payload: dict[str, object], _as_json: bool) -> None:
    raise ImportError("cannot import name 'new_link'")


def test_a_stale_renderer_still_prints_the_json_result() -> None:
    payload: dict[str, object] = {"status": "updated", "changed": True, "message": "Updated."}
    out = io.StringIO()
    emit_update_result(_broken_emit, payload, True, stream=out)
    assert json.loads(out.getvalue()) == payload


def test_a_stale_renderer_still_prints_the_text_result() -> None:
    out = io.StringIO()
    emit_update_result(_broken_emit, {"message": "Updated HOL Guard."}, False, stream=out)
    assert out.getvalue().splitlines()[0] == "Updated HOL Guard."


def test_a_working_renderer_is_used() -> None:
    seen: list[tuple[str, dict[str, object], bool]] = []
    emit_update_result(lambda *call: seen.append(call), {"status": "current"}, False)
    assert seen == [("update", {"status": "current"}, False)]


def _run_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, dry_run: bool) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(dispatch, "load_package_before_install", lambda: calls.append("preload") or 0)
    monkeypatch.setattr(dispatch, "_migrate_legacy_macos_secrets", lambda _store: None, raising=False)

    def update(**_kwargs: object) -> tuple[dict[str, object], int]:
        calls.append("install")
        return {"status": "updated", "changed": True, "message": "Updated."}, 0

    monkeypatch.setattr(dispatch, "run_guard_update", update)
    monkeypatch.setattr(dispatch, "_emit", lambda *_call: calls.append("emit"))
    args = argparse.Namespace(dry_run=dry_run, json=True, alpha=False, wheel=None, force_pypi_reinstall=False)
    assert dispatch._run_guard_update_command(args, guard_home=tmp_path) == 0
    return calls


def test_an_update_loads_the_package_before_it_installs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_update(tmp_path, monkeypatch, dry_run=False) == ["preload", "install", "emit"]


def test_a_dry_run_installs_nothing_and_skips_the_preload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_update(tmp_path, monkeypatch, dry_run=True) == ["install", "emit"]
