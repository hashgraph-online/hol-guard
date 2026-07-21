"""Runner regressions for incomplete skill-directory identity approvals."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def test_fresh_approval_survives_unchanged_incomplete_skill_redetection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    skill_dir = home_dir / ".gemini" / "skills" / "review"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Review\n", encoding="utf-8")
    try:
        (skill_dir / "broken-reference").symlink_to("missing-reference.md")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir)
    detect_count = 0

    def detect(_harness: str, _context: HarnessContext):
        nonlocal detect_count
        detect_count += 1
        return GeminiHarnessAdapter().detect(context)

    def allow_once(_detection, evaluation: dict[str, object]) -> dict[str, object]:
        items = evaluation.get("artifacts")
        assert isinstance(items, list)
        item = items[0]
        assert isinstance(item, dict)
        assert item["policy_action"] == "require-reapproval"
        item["policy_action"] = "allow"
        item["user_override"] = "allow-once"
        evaluation["blocked"] = False
        return evaluation

    launch_calls: list[object] = []
    monkeypatch.setattr(guard_runner_module, "detect_harness", detect)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: (
            launch_calls.append((args, kwargs))
            or subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        ),
    )

    result = guard_runner_module.guard_run(
        "gemini",
        context,
        GuardStore(home_dir),
        GuardConfig(guard_home=home_dir, workspace=workspace_dir),
        dry_run=False,
        passthrough_args=[],
        interactive_resolver=allow_once,
    )

    assert detect_count >= 2
    assert result["blocked"] is False
    assert result["artifacts"][0]["policy_action"] == "allow"
    assert result["artifacts"][0]["trusted_request_override"]["applied"] is True
