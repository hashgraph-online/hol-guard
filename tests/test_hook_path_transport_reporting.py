"""Hook path transport errors keep caller-visible parameter names."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as module


@pytest.mark.parametrize("label", ["exec-workdir", "workspace-payload", "workspace-query"])
def test_unavailable_resident_reports_workspace_not_internal_label(
    monkeypatch: pytest.MonkeyPatch, tmp_path, label: str
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise module.NativeDirectoryTrustError("native_directory_trust_unavailable")

    monkeypatch.setattr(module, "native_directory_trust", unavailable)
    daemon_server = SimpleNamespace(
        store=SimpleNamespace(guard_home=tmp_path / "guard-home"),
        home_dir=tmp_path / "home",
    )
    handler = SimpleNamespace(_daemon_server=lambda: daemon_server)
    with pytest.raises(module._HookPathValidationError) as error:
        module._GuardDaemonHandler._settled_hook_directories(handler, (label, "project", "hook-workspace"))
    assert error.value.parameter == "workspace"
    assert error.value.reason == module._DIRECTORY_TRUST_UNAVAILABLE
