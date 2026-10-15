"""Explicit questionnaire preference for tests of the existing approval workflows."""

from __future__ import annotations

import inspect
from functools import wraps
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _read_toml(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


@pytest.fixture
def approval_questionnaire_mode(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.store import GuardStore

    original_init = config.GuardConfig.__init__
    signature = inspect.signature(original_init)

    @wraps(original_init)
    def init_with_questionnaire(self, *args, **kwargs):
        bound = signature.bind_partial(self, *args, **kwargs)
        if "blocked_request_mode" not in bound.arguments:
            kwargs["blocked_request_mode"] = "ask"
        original_init(self, *args, **kwargs)

    original_load = config.load_native_guard_config

    @wraps(original_load)
    def load_with_questionnaire(guard_home, workspace, **kwargs):
        # Model the operator preference in synthetic Guard configuration only.
        # Explicit modes in any config file always win, including safe-alternative.
        loaded = original_load(guard_home, workspace, **kwargs)
        paths = [guard_home / "config.toml"]
        if workspace is not None:
            paths.extend(workspace / name for name in (".ai-plugin-scanner-guard.toml", ".hol-guard.toml"))
        if not any("blocked_request_mode" in _read_toml(path) for path in paths):
            loaded["blocked_request_mode"] = "ask"
        return loaded

    monkeypatch.setattr(config.GuardConfig, "__init__", init_with_questionnaire)
    monkeypatch.setattr(config, "load_native_guard_config", load_with_questionnaire)

    original_store_init = GuardStore.__init__

    @wraps(original_store_init)
    def store_with_questionnaire(self, guard_home, *args, **kwargs):
        # Daemon workers are separate processes: persist the same explicit test
        # preference in their temporary home rather than relying on monkeypatch.
        if guard_home.resolve().is_relative_to(tmp_path.resolve()):
            path = guard_home / "config.toml"
            if "blocked_request_mode" not in _read_toml(path):
                existing = path.read_text(encoding="utf-8") if path.exists() else ""
                guard_home.mkdir(parents=True, exist_ok=True)
                path.write_text('blocked_request_mode = "ask"\n' + existing, encoding="utf-8")
        original_store_init(self, guard_home, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "__init__", store_with_questionnaire)
