"""Security regressions for complete Hermes parsing, hashing, and previews."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import hermes_file_inspection as inspection_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.adapters.hermes_file_inspection import (
    HERMES_CONFIG_MAX_BYTES,
    HERMES_CONFIG_MAX_DEPTH,
    HERMES_CONFIG_MAX_NODES,
    HERMES_PREVIEW_BYTES,
    inspect_hermes_config,
    inspect_hermes_text_file,
)
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.risk import artifact_risk_signals_typed


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path,
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _skill(tmp_path: Path) -> Path:
    return _write(
        tmp_path / ".hermes" / "skills" / "dev" / "complete" / "SKILL.md",
        "---\nname: complete\n---\n# Complete\n",
    )


def _artifact(detection: HarnessDetection, artifact_type: str) -> GuardArtifact:
    return next(item for item in detection.artifacts if item.artifact_type == artifact_type)


def test_skill_subfile_suffix_changes_full_hash_and_parent_directory_identity(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    script = _write(
        skill.parent / "scripts" / "large.sh",
        "# safe preview\n" + ("# padding\n" * 8_000) + "echo first-suffix\n",
    )
    adapter = HermesHarnessAdapter()

    before = adapter.detect(_context(tmp_path))
    before_file = _artifact(before, "skill_file")
    before_skill = _artifact(before, "skill")
    script.write_text(script.read_text(encoding="utf-8").replace("first-suffix", "other-suffix"), encoding="utf-8")
    after = adapter.detect(_context(tmp_path))
    after_file = _artifact(after, "skill_file")
    after_skill = _artifact(after, "skill")

    assert before_file.metadata["analysis_truncated"] is True
    before_preview_bytes = before_file.metadata["preview_bytes"]
    assert isinstance(before_preview_bytes, int)
    assert before_preview_bytes <= HERMES_PREVIEW_BYTES
    assert "first-suffix" not in " ".join(before_file.args)
    assert before_file.metadata["content_hash"] != after_file.metadata["content_hash"]
    assert before_skill.metadata["directory_hash"] != after_skill.metadata["directory_hash"]
    assert artifact_hash(before_file) != artifact_hash(after_file)
    assert any(
        signal.signal_id == "inspection:analysis-truncated" for signal in artifact_risk_signals_typed(before_file)
    )


def test_yaml_server_after_old_preview_limit_is_parsed_from_complete_config(tmp_path: Path) -> None:
    config = _write(
        tmp_path / ".hermes" / "config.yaml",
        ("# bounded preview padding\n" * 3_000)
        + "mcp_servers:\n  suffix-server:\n    command: python\n    args: ['-m', 'suffix']\n",
    )

    detection = HermesHarnessAdapter().detect(_context(tmp_path))

    server = next(item for item in detection.artifacts if item.artifact_type == "mcp_server")
    assert config.stat().st_size > HERMES_PREVIEW_BYTES
    assert server.name == "suffix-server"
    assert server.args == ("-m", "suffix")


def test_json_server_after_old_preview_limit_is_parsed_from_complete_config(tmp_path: Path) -> None:
    config = _write(
        tmp_path / ".hermes" / "mcp_servers.json",
        json.dumps(
            {
                "padding": {"enabled": False, "description": "x" * (HERMES_PREVIEW_BYTES + 1)},
                "suffix-server": {"command": "node", "args": ["suffix.js"]},
            }
        ),
    )

    detection = HermesHarnessAdapter().detect(_context(tmp_path))

    servers = [item for item in detection.artifacts if item.artifact_type == "mcp_server"]
    assert config.stat().st_size > HERMES_PREVIEW_BYTES
    assert [item.name for item in servers] == ["suffix-server"]


def test_oversized_config_is_hashed_but_never_partially_parsed(tmp_path: Path) -> None:
    config = _write(
        tmp_path / ".hermes" / "config.yaml",
        ("# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" * 40_000)
        + "mcp_servers:\n  hidden:\n    command: bash\n",
    )
    assert config.stat().st_size > HERMES_CONFIG_MAX_BYTES

    detection = HermesHarnessAdapter().detect(_context(tmp_path))
    issue = next(item for item in detection.artifacts if item.artifact_type == "configuration")

    assert not any(item.artifact_type == "mcp_server" for item in detection.artifacts)
    assert issue.metadata["config_reason"] == "file_too_large"
    assert issue.metadata["content_hash"] == f"sha256:{hashlib.sha256(config.read_bytes()).hexdigest()}"
    preview_bytes = issue.metadata["preview_bytes"]
    assert isinstance(preview_bytes, int)
    assert preview_bytes <= HERMES_PREVIEW_BYTES
    assert any("no partial configuration" in warning for warning in detection.warnings)


def test_config_parse_buffer_enforces_exact_byte_limit(tmp_path: Path) -> None:
    at_limit = _write(
        tmp_path / "at-limit.json",
        (" " * (HERMES_CONFIG_MAX_BYTES - 2)) + "{}",
    )
    over_limit = _write(
        tmp_path / "over-limit.json",
        (" " * (HERMES_CONFIG_MAX_BYTES - 2)) + "{} ",
    )

    accepted = inspect_hermes_config(at_limit, syntax="json")
    rejected = inspect_hermes_config(over_limit, syntax="json")

    assert accepted.complete is True
    assert accepted.file.size_bytes == HERMES_CONFIG_MAX_BYTES
    assert accepted.payload == {}
    assert rejected.complete is False
    assert rejected.file.size_bytes == HERMES_CONFIG_MAX_BYTES + 1
    assert rejected.file.content is None
    assert rejected.reason == "file_too_large"


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        (
            "duplicate.yaml",
            "mcp_servers:\n  same: {command: python}\n  same: {command: bash}\n",
            "config_duplicate_key",
        ),
        (
            "alias.yaml",
            "defaults: &defaults {command: python}\nmcp_servers: {same: *defaults}\n",
            "config_alias_limit_exceeded",
        ),
        (
            "duplicate.json",
            '{"same":{"command":"python"},"same":{"command":"bash"}}',
            "config_duplicate_key",
        ),
    ],
)
def test_duplicate_keys_and_yaml_aliases_fail_closed(
    tmp_path: Path,
    name: str,
    content: str,
    reason: str,
) -> None:
    path = _write(tmp_path / name, content)
    syntax = "json" if path.suffix == ".json" else "yaml"

    inspection = inspect_hermes_config(path, syntax=syntax)  # type: ignore[arg-type]

    assert inspection.complete is False
    assert inspection.reason == reason
    assert inspection.payload is None


def test_excessive_json_depth_fails_closed(tmp_path: Path) -> None:
    value = "null"
    for _ in range(HERMES_CONFIG_MAX_DEPTH + 2):
        value = '{"nested":' + value + "}"
    path = _write(tmp_path / "deep.json", value)

    inspection = inspect_hermes_config(path, syntax="json")

    assert inspection.complete is False
    assert inspection.reason == "config_depth_limit_exceeded"


def test_excessive_json_node_count_fails_closed(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "many-nodes.json",
        json.dumps({"items": [None] * HERMES_CONFIG_MAX_NODES}),
    )

    inspection = inspect_hermes_config(path, syntax="json")

    assert inspection.complete is False
    assert inspection.reason == "config_node_limit_exceeded"


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_nonfinite_json_numbers_fail_closed(tmp_path: Path, constant: str) -> None:
    path = _write(tmp_path / "nonfinite.json", f'{{"value":{constant}}}')

    inspection = inspect_hermes_config(path, syntax="json")

    assert inspection.complete is False
    assert inspection.reason == "config_value_invalid"


@pytest.mark.parametrize(
    "content",
    (
        "mcp_servers:\n  same: {command: python}\n  same: {command: bash}\n",
        "# padding\n" * (HERMES_CONFIG_MAX_BYTES // 10 + 1),
    ),
)
def test_install_refuses_incomplete_config_without_writing_managed_bundle(
    tmp_path: Path,
    content: str,
) -> None:
    config = _write(tmp_path / ".hermes" / "config.yaml", content)
    original = config.read_bytes()
    context = _context(tmp_path)

    with pytest.raises(ValueError, match="Hermes config inspection failed"):
        HermesHarnessAdapter().install(context)

    managed_root = context.guard_home / "hermes"
    assert config.read_bytes() == original
    assert not (managed_root / "mcp-overlay.json").exists()
    assert not (managed_root / "pretool-hook.json").exists()
    assert not (managed_root / "manifest.json").exists()
    assert not (context.guard_home / "bin" / "guard-hermes").exists()
    assert not (context.guard_home / "bin" / "guard-hermes.cmd").exists()


def test_invalid_utf8_skill_is_explicitly_incomplete_and_non_reusable(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    skill.write_bytes(b"---\nname: invalid\n---\n\xff")

    artifact = _artifact(HermesHarnessAdapter().detect(_context(tmp_path)), "skill")

    assert artifact.metadata["inspection_complete"] is False
    assert artifact.metadata["inspection_reason"] == "file_invalid_utf8"
    assert artifact.metadata["content_hash"] == f"sha256:{hashlib.sha256(skill.read_bytes()).hexdigest()}"
    assert any(signal.signal_id == "inspection:incomplete" for signal in artifact_risk_signals_typed(artifact))


def test_skill_symlink_escape_marks_directory_identity_incomplete(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    outside = _write(tmp_path / "outside.sh", "echo outside\n")
    link = skill.parent / "scripts" / "outside.sh"
    link.parent.mkdir()
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    detection = HermesHarnessAdapter().detect(_context(tmp_path))
    primary = _artifact(detection, "skill")
    subfile = _artifact(detection, "skill_file")

    identity = primary.metadata["skillDirectoryIdentity"]
    assert isinstance(identity, dict)
    assert identity["status"] == "incomplete"
    assert identity["reason"] == "symlink_escape"
    assert subfile.metadata["inspection_reason"] == "file_symlink_unsupported"
    assert detection.warnings


def test_file_change_during_streaming_hash_is_not_reported_complete(tmp_path: Path, monkeypatch) -> None:
    path = _write(tmp_path / "large.md", "a" * (HERMES_PREVIEW_BYTES * 2))
    original_read = inspection_module.os.read
    changed = False

    def replacing_read(descriptor: int, amount: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, amount)
        if chunk and not changed:
            changed = True
            path.write_text("replacement", encoding="utf-8")
        return chunk

    monkeypatch.setattr(inspection_module.os, "read", replacing_read)

    inspection = inspect_hermes_text_file(path)

    assert inspection.complete is False
    assert inspection.reason == "file_changed_during_read"
    assert inspection.content_hash is None


def test_unreadable_file_failure_is_typed(tmp_path: Path, monkeypatch) -> None:
    path = _write(tmp_path / "unreadable.md", "content")
    original_open = inspection_module.os.open

    def denied_open(
        candidate: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        if Path(os.fsdecode(candidate)) == path:
            raise PermissionError("denied")
        return original_open(candidate, flags, mode)

    monkeypatch.setattr(inspection_module.os, "open", denied_open)

    inspection = inspect_hermes_text_file(path)

    assert inspection.complete is False
    assert inspection.readable is False
    assert inspection.reason == "file_unreadable"
