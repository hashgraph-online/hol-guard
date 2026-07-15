from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import native


def test_unsupported_platform_never_reports_healthy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native.platform, "system", lambda: "Linux")
    result = native.verify_native_install(tmp_path)
    assert not result.healthy
    assert result.reason_code == "native_platform_unsupported"
