"""Generic publisher inputs retain their captured bytes and non-file refusal."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs


def test_generic_regular_input_capture_binds_the_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "control-input.toml"
    content = b"enabled = true\n"
    path.write_bytes(content)

    captured = NativePolicySnapshotPublisherInputs._capture_policy_input(path)

    assert captured.content == content
    assert captured.identity[1] == hashlib.sha256(content).hexdigest()


def test_generic_directory_capture_refuses_before_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "control-input.toml"
    path.mkdir()

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("a non-regular input must not be opened")

    monkeypatch.setattr("codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs.os.open", unexpected_open)

    captured = NativePolicySnapshotPublisherInputs._capture_policy_input(path)

    assert captured.content == b""
    assert captured.identity == ("not-file", path.stat().st_mode)
