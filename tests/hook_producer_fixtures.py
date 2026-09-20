"""Patch the initial and refreshed runtime hook producers consistently."""

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.cli import commands_hook as hook_command
from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as artifact_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact


def patch_runtime_hook_producers(
    monkeypatch: pytest.MonkeyPatch, *, config: GuardConfig, artifact: GuardArtifact
) -> None:
    for module in (hook_command, config_module):
        monkeypatch.setattr(module, "load_guard_config", lambda *_args, **_kwargs: config)
    for module in (hook_command, artifact_module):
        monkeypatch.setattr(module, "_hook_runtime_artifact", lambda **_kwargs: artifact)
