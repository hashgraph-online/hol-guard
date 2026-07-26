"""Regression coverage for Pi ``skill://`` post-tool reads."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore

SKILL_URI = "skill://test-skill"
Context = tuple[Path, Path, Path, HookWorker]


@pytest.fixture()
def context(tmp_path: Path) -> Context:
    workspace = tmp_path / "workspace"
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir()
    home_dir.mkdir()
    guard_home.mkdir()
    return workspace, home_dir, guard_home, HookWorker(store=GuardStore(guard_home))


def _install_skill(home_dir: Path, content: str) -> Path:
    skill_file = home_dir / ".codex" / "skills" / "test-skill" / "SKILL.md"
    _ = skill_file.parent.mkdir(parents=True)
    _ = skill_file.write_text(content)
    return skill_file


def _review(
    context: Context,
    *,
    output: str,
    uri: str = SKILL_URI,
    source_ref_uri: str | None = None,
    output_truncated: bool = False,
) -> dict[str, object]:
    workspace, home_dir, guard_home, worker = context
    ref_uri = source_ref_uri or uri
    payload: dict[str, object] = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"path": uri},
        "tool_response": output,
        "guard_source_ref": {
            "version": 1,
            "path": ref_uri,
            "output_sha256": sha256_text(output),
            "output_chars": len(output),
            "tool_input_path": ref_uri,
        },
        "tool_response_summary": {
            "version": 1,
            "output_chars": len(output),
            "excerpt": output,
            "excerpt_truncated": output_truncated,
        },
    }
    return worker.review_http_payload(
        payload=payload,
        params={},
        default_harness="pi",
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace,
    )


def test_verified_skill_uri_returns_allow_original(context: Context) -> None:
    _, home_dir, *_ = context
    content = "# Test skill\n\nFollow these instructions for routine work.\n"
    _ = _install_skill(home_dir, content)

    result = _review(context, output=content.rstrip("\n"))

    assert result["decision"] == "allow"
    assert result["model_output_action"] == "allow_original"
    assert result["reason_code"] == "source_full_scan_allow"


def test_changed_skill_output_is_not_allowed(context: Context) -> None:
    _, home_dir, *_ = context
    _ = _install_skill(home_dir, "# Safe skill\n")

    result = _review(context, output="# Different output")

    assert result["model_output_action"] != "allow_original"


def test_missing_skill_uri_is_not_allowed(context: Context) -> None:
    result = _review(context, output="missing", uri="skill://missing")

    assert result["model_output_action"] != "allow_original"


def test_traversing_skill_uri_is_not_allowed(context: Context) -> None:
    result = _review(context, output="safe", uri="skill://../../etc/passwd")

    assert result["model_output_action"] != "allow_original"


def test_skill_document_symlink_escape_is_not_allowed(context: Context, tmp_path: Path) -> None:
    _, home_dir, *_ = context
    outside = tmp_path / "outside.md"
    _ = outside.write_text("safe")
    skill_file = home_dir / ".codex" / "skills" / "test-skill" / "SKILL.md"
    _ = skill_file.parent.mkdir(parents=True)
    _ = skill_file.symlink_to(outside)

    result = _review(context, output="safe")

    assert result["model_output_action"] != "allow_original"


def test_ordinary_file_target_mismatch_is_not_allowed(context: Context) -> None:
    workspace, *_ = context
    _ = (workspace / "first.md").write_text("safe")
    _ = (workspace / "second.md").write_text("safe")

    result = _review(
        context,
        output="safe",
        uri="second.md",
        source_ref_uri="first.md",
    )

    assert result["model_output_action"] != "allow_original"


def test_local_virtual_resource_uses_bounded_output_scan(context: Context) -> None:
    result = _review(context, output="# Pasted objective", uri="local://paste-1.md")

    assert result["decision"] == "allow"
    assert result["model_output_action"] == "allow_original"
    assert result["reason_code"] == "output_scan_allow"


def test_local_virtual_resource_with_secret_is_blocked(context: Context) -> None:
    result = _review(
        context,
        output="token: ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        uri="local://paste-1.md",
    )

    assert result["decision"] == "deny"
    assert result["reason_code"] == "output_secret_match"


def test_truncated_local_virtual_resource_is_not_returned_in_full(context: Context) -> None:
    result = _review(
        context,
        output="# Partial pasted objective",
        uri="local://paste-1.md",
        output_truncated=True,
    )

    assert result["model_output_action"] != "allow_original"
    assert result["reason_code"] == "output_too_large"


def test_skill_with_secret_is_blocked(context: Context) -> None:
    _, home_dir, *_ = context
    content = "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
    _ = _install_skill(home_dir, content)

    result = _review(context, output=content.rstrip("\n"))

    assert result["decision"] == "deny"
    assert result["reason_code"] == "source_secret_match"
