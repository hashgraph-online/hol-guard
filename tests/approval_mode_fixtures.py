"""Explicit questionnaire preference for tests of the existing approval workflows."""

from __future__ import annotations

import inspect
from functools import wraps

import pytest


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

    original_read = config._read_toml

    @wraps(original_read)
    def read_with_questionnaire(*args, **kwargs):
        # Model the operator preference in synthetic Guard configuration only.
        # Explicit modes in a test always win, including safe-alternative.
        return {"blocked_request_mode": "ask", **original_read(*args, **kwargs)}

    monkeypatch.setattr(config.GuardConfig, "__init__", init_with_questionnaire)
    monkeypatch.setattr(config, "_read_toml", read_with_questionnaire)

    original_store_init = GuardStore.__init__

    @wraps(original_store_init)
    def store_with_questionnaire(self, guard_home, *args, **kwargs):
        # Daemon workers are separate processes: persist the same explicit test
        # preference in their temporary home rather than relying on monkeypatch.
        if guard_home.resolve().is_relative_to(tmp_path.resolve()):
            path = guard_home / "config.toml"
            payload = original_read(path)
            if "blocked_request_mode" not in payload:
                config._write_guard_config(path, {**payload, "blocked_request_mode": "ask"})
        original_store_init(self, guard_home, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "__init__", store_with_questionnaire)
