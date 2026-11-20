from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_integrity as integrity
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from tests.codex_hook_paths_support import hook_authority_receipt_path, hook_manifest_path, hook_secret_path


def test_the_runtime_names_the_files_the_test_helpers_derive(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    for config in (real / "config.toml", tmp_path / "link" / "config.toml", tmp_path / "missing" / "config.toml"):
        paths = integrity.hook_paths(guard_home, config)
        assert paths.manifest == hook_manifest_path(guard_home, config)
        assert paths.receipt == hook_authority_receipt_path(guard_home, config)
        assert paths.key == hook_secret_path(guard_home)
        assert integrity.hook_manifest_file(guard_home, config) == paths.manifest
    assert integrity.hook_secret_file(guard_home) == hook_secret_path(guard_home)


def test_a_relative_config_is_named_from_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    guard_home = tmp_path / "guard-home"
    assert integrity.hook_manifest_file(guard_home, Path("config.toml")) == hook_manifest_path(
        guard_home, tmp_path / "config.toml"
    )


@pytest.mark.parametrize(
    "answer",
    [None, {}, {"key_path": ""}, {"key_path": 3}, {"manifest_path": "/m", "key_path": "/k"}],
)
def test_a_runtime_that_does_not_name_the_target_files_is_a_refused_operation(
    answer: dict[str, object] | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", lambda *_a, **_k: answer)
    with pytest.raises(CodexHookIntegrityError) as raised:
        integrity.hook_paths(tmp_path / "guard-home", tmp_path / "config.toml")
    assert raised.value.reason == "codex_hook_manifest_verification_unavailable"


@pytest.mark.parametrize("answer", [None, {}, {"key_path": ""}, {"key_path": 3}])
def test_a_runtime_that_does_not_name_the_key_is_a_refused_operation(
    answer: dict[str, object] | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", lambda *_a, **_k: answer)
    with pytest.raises(CodexHookIntegrityError) as raised:
        integrity.hook_secret_file(tmp_path / "guard-home")
    assert raised.value.reason == "codex_hook_manifest_verification_unavailable"
