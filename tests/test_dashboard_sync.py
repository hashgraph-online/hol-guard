"""Tests for dashboard asset sync source selection."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture()
def dashboard_sync_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load dashboard_sync without importing the full guard CLI dependency graph."""
    for name in [
        "codex_plugin_scanner",
        "codex_plugin_scanner.guard",
        "codex_plugin_scanner.guard.cli",
    ]:
        package = types.ModuleType(name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, name, package)
    redaction = types.ModuleType("codex_plugin_scanner.guard.redaction")
    redaction.redact_sensitive_text = lambda value: value
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.guard.redaction", redaction)

    module_name = "codex_plugin_scanner.guard.cli.dashboard_sync"
    module_path = (
        Path(__file__).resolve().parents[1] / "src" / "codex_plugin_scanner" / "guard" / "cli" / "dashboard_sync.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _write_source_markers(path: Path) -> None:
    (path / "dashboard").mkdir(parents=True)
    (path / "dashboard" / "package.json").write_text("{}\n", encoding="utf-8")
    (path / "src" / "codex_plugin_scanner").mkdir(parents=True)


def test_find_source_checkout_does_not_discover_spoofed_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dashboard_sync_module: ModuleType,
) -> None:
    attacker_checkout = tmp_path / "attacker-project"
    _write_source_markers(attacker_checkout)
    (attacker_checkout / ".git").mkdir()
    (attacker_checkout / ".git" / "config").write_text(
        '[remote "origin"]\nurl = https://evil.example/repo.git?note=hashgraph-online/hol-guard\n',
        encoding="utf-8",
    )

    monkeypatch.chdir(attacker_checkout)
    monkeypatch.delenv(dashboard_sync_module._DASHBOARD_SYNC_SOURCE_ENV, raising=False)

    assert dashboard_sync_module.find_source_checkout() is None


def test_find_source_checkout_requires_explicit_source_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dashboard_sync_module: ModuleType,
) -> None:
    source_checkout = tmp_path / "hol-guard"
    _write_source_markers(source_checkout)
    unrelated_cwd = tmp_path / "workspace"
    unrelated_cwd.mkdir()

    monkeypatch.chdir(unrelated_cwd)
    monkeypatch.setenv(dashboard_sync_module._DASHBOARD_SYNC_SOURCE_ENV, str(source_checkout))

    assert dashboard_sync_module.find_source_checkout() == source_checkout.resolve()


def test_verify_source_checkout_ignores_spoofable_git_config(
    tmp_path: Path,
    dashboard_sync_module: ModuleType,
) -> None:
    source_checkout = tmp_path / "hol-guard"
    _write_source_markers(source_checkout)
    (source_checkout / ".git").mkdir()
    (source_checkout / ".git" / "config").write_text(
        '[remote "origin"]\nurl = https://evil.example/repo.git?note=hashgraph-online/hol-guard\n',
        encoding="utf-8",
    )

    assert dashboard_sync_module.verify_source_checkout(source_checkout) == source_checkout
