"""Tests for Guard init plan tray integration.

Validates that the init plan includes the tray step by default, that
``--skip-tray`` causes the tray step to be skipped via ``_approve_init_step``,
and that non-interactive init does not approve the tray step (so no
persistence is created).

Design note: ``_build_init_plan`` always returns the tray step; skipping is
handled by ``_approve_init_step`` checking the ``skip_flag`` attribute on the
step dict.
"""

from __future__ import annotations

import argparse

import pytest

from codex_plugin_scanner.guard.cli.commands_support_workspace import (
    _approve_init_step,
    _build_init_plan,
)

# ---------------------------------------------------------------------------
# _build_init_plan — tray step is always present
# ---------------------------------------------------------------------------


class TestBuildInitPlan:
    def test_plan_contains_tray_step(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        tray_steps = [s for s in plan if s["id"] == "tray"]
        assert len(tray_steps) == 1

        tray = tray_steps[0]
        assert tray["title"] == "Install menu bar / tray icon"
        assert tray["skip_flag"] == "skip_tray"

    def test_plan_step_count_and_order(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        step_ids = [s["id"] for s in plan]
        assert step_ids == [
            "dashboard",
            "apps",
            "cloud",
            "notifications",
            "tray",
        ]

    def test_tray_step_command_contains_install_and_start(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        tray = next(s for s in plan if s["id"] == "tray")

        assert "tray install" in str(tray["command"])
        assert "tray start" in str(tray["command"])

    def test_build_init_plan_ignores_args(self) -> None:
        """_build_init_plan currently ignores its args — passing arbitrary
        fields should not raise and always returns the full plan including
        tray (even if --skip-tray is set)."""
        plan = _build_init_plan(
            argparse.Namespace(
                skip_tray=True,
            ),
        )
        # Tray step is always present regardless of skip flags.
        assert any(s["id"] == "tray" for s in plan)


# ---------------------------------------------------------------------------
# _approve_init_step — skip_tray / yes / noninteractive / interactive
# ---------------------------------------------------------------------------


class TestApproveInitStepTray:
    def _make_tray_step(self) -> dict[str, object]:
        return {
            "id": "tray",
            "title": "Install menu bar / tray icon",
            "command": "hol-guard tray install && hol-guard tray start",
            "skip_flag": "skip_tray",
        }

    def test_skip_tray_flag_skips_tray_step(self) -> None:
        tray_step = self._make_tray_step()
        args = argparse.Namespace(skip_tray=True)

        result = _approve_init_step(args, tray_step, interactive=True)

        assert result is False
        assert tray_step["decision"] == "skipped"
        assert tray_step["reason"] == "skip_tray"

    def test_yes_flag_approves_tray_step(self) -> None:
        tray_step = self._make_tray_step()
        args = argparse.Namespace(yes=True)

        result = _approve_init_step(args, tray_step, interactive=False)

        assert result is True
        assert tray_step["decision"] == "approved"
        assert tray_step["reason"] == "yes_flag"

    def test_interactive_mode_user_says_no(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Interactive mode with 'n' response skips the step."""
        tray_step = self._make_tray_step()
        args = argparse.Namespace()

        monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")
        result = _approve_init_step(args, tray_step, interactive=True)

        assert result is False
        assert tray_step["decision"] == "skipped"
        assert tray_step["reason"] == "user_skipped"

    def test_interactive_mode_user_says_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Interactive mode with 'y' response approves the step."""
        tray_step = self._make_tray_step()
        args = argparse.Namespace()

        monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")
        result = _approve_init_step(args, tray_step, interactive=True)

        assert result is True
        assert tray_step["decision"] == "approved"
        assert tray_step["reason"] == "user_approved"

    def test_noninteractive_skips_tray_without_yes_flag(self) -> None:
        """Non-interactive init does not approve any step, so no persistence
        is created.

        This confirms that ``noninteractive init --skip-tray`` is redundant —
        the tray step is skipped regardless because interactive is False.
        """
        tray_step = self._make_tray_step()
        args = argparse.Namespace()

        result = _approve_init_step(args, tray_step, interactive=False)

        assert result is False
        assert tray_step["decision"] == "skipped"
        assert tray_step["reason"] == "needs_approval"

    def test_noninteractive_skip_tray_flag_also_skips(self) -> None:
        """--skip-tray in non-interactive mode also skips the tray step."""
        tray_step = self._make_tray_step()
        args = argparse.Namespace(skip_tray=True)

        result = _approve_init_step(args, tray_step, interactive=False)

        assert result is False
        assert tray_step["decision"] == "skipped"
        assert tray_step["reason"] == "skip_tray"


# ---------------------------------------------------------------------------
# Integration: full plan + approve with skip_tray
# ---------------------------------------------------------------------------


class TestSkipTrayIntegration:
    def test_full_plan_with_skip_tray_is_skipped(self) -> None:
        """Simulate processing the full init plan with --skip-tray."""
        plan = _build_init_plan(
            argparse.Namespace(skip_tray=True),
        )
        args = argparse.Namespace(skip_tray=True)

        tray_step = next(s for s in plan if s["id"] == "tray")
        result = _approve_init_step(args, tray_step, interactive=False)

        assert result is False
        assert tray_step["decision"] == "skipped"
        assert tray_step["reason"] == "skip_tray"

    def test_full_plan_with_yes_approves_all(self) -> None:
        """--yes approves every step, including tray."""
        plan = _build_init_plan(argparse.Namespace(yes=True))
        args = argparse.Namespace(yes=True)

        for step in plan:
            _approve_init_step(args, step, interactive=False)
            assert step["decision"] == "approved"
            assert step["reason"] == "yes_flag"


# ---------------------------------------------------------------------------
# Plan structure
# ---------------------------------------------------------------------------


class TestPlanStructure:
    def test_all_steps_have_skip_flags_or_none(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        for step in plan:
            skip = step.get("skip_flag")
            assert skip is None or isinstance(skip, str)

    def test_dashboard_has_no_skip_flag(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        dashboard = next(s for s in plan if s["id"] == "dashboard")
        assert dashboard["skip_flag"] is None

    def test_each_non_dashboard_step_has_a_skip_flag(self) -> None:
        plan = _build_init_plan(argparse.Namespace())
        for step in plan:
            if step["id"] != "dashboard":
                assert isinstance(step["skip_flag"], str) and step["skip_flag"]
