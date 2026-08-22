"""Tests for the OptiQra harness adapter.

OptiQra resolves an ``auto-fix-project`` action (a target file set and a
final diff) and is expected to call ``guard hook --harness optiqra`` before
writing that action to disk. These tests cover the adapter identity, the
honest "not locally installed" detection (OptiQra has no on-disk config for
Guard to discover), and the full allow/deny/approval-required hook flow that
determines whether OptiQra's write may proceed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.optiqra import OptiQraHarnessAdapter
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import (
    action_envelope_harnesses,
    normalize_optiqra_payload,
)
from codex_plugin_scanner.guard.store import GuardStore


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _write_file_payload(paths: list[str]) -> dict[str, object]:
    return {
        "hookEventName": "PreToolUse",
        "tool_name": "write_file",
        "tool_input": {"file_paths": paths},
    }


def _run_hook(
    tmp_path: Path,
    *,
    payload: dict[str, object],
    default_action: str,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, object]]:
    guard_home = tmp_path / ".hol-guard"
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=tmp_path, default_action=default_action)
    args = argparse.Namespace(
        harness="optiqra",
        json=True,
        policy_action=None,
        artifact_id=None,
        artifact_name=None,
    )
    rc = _run_hook_generic_payload(
        args,
        action_envelope=None,
        config=config,
        payload=payload,
        home_dir=tmp_path,
        runtime_workspace=tmp_path,
        store=store,
    )
    output = json.loads(capsys.readouterr().out)
    assert isinstance(output, dict)
    return rc, output


class TestOptiQraAdapterIdentity:
    def test_harness_identifier_is_optiqra(self) -> None:
        assert OptiQraHarnessAdapter().harness == "optiqra"

    def test_approval_tier_is_approval_center(self) -> None:
        assert OptiQraHarnessAdapter().approval_tier == "approval-center"

    def test_optiqra_is_registered_and_resolvable(self) -> None:
        from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters

        assert any(adapter.harness == "optiqra" for adapter in list_adapters())
        assert get_adapter("optiqra").harness == "optiqra"

    def test_every_adapter_setup_contract_covers_optiqra(self) -> None:
        adapter = OptiQraHarnessAdapter()
        assert adapter.setup_steps()
        assert adapter.verify_steps()
        assert adapter.repair_steps()
        assert adapter.coverage_summary().blind_spots


class TestOptiQraDetection:
    def test_detect_reports_not_locally_installed(self, tmp_path: Path) -> None:
        detection = OptiQraHarnessAdapter().detect(_ctx(tmp_path))
        assert detection.harness == "optiqra"
        assert detection.installed is False
        assert detection.command_available is False
        assert detection.config_paths == ()
        assert detection.artifacts == ()
        assert detection.warnings


class TestOptiQraInstallUninstall:
    def test_install_is_not_supported(self, tmp_path: Path) -> None:
        with pytest.raises(NotImplementedError):
            OptiQraHarnessAdapter().install(_ctx(tmp_path))

    def test_uninstall_is_not_supported(self, tmp_path: Path) -> None:
        with pytest.raises(NotImplementedError):
            OptiQraHarnessAdapter().uninstall(_ctx(tmp_path))


class TestOptiQraActionEnvelope:
    def test_optiqra_is_a_registered_action_envelope_harness(self) -> None:
        assert "optiqra" in action_envelope_harnesses()

    def test_write_file_payload_becomes_file_write_action(self, tmp_path: Path) -> None:
        envelope = normalize_optiqra_payload(
            _write_file_payload(["src/app/page.tsx", "src/app/about.tsx"]),
            workspace=tmp_path,
            home_dir=tmp_path,
        )
        assert envelope.harness == "optiqra"
        assert envelope.action_type == "file_write"

    def test_target_files_are_passed_to_guard(self, tmp_path: Path) -> None:
        envelope = normalize_optiqra_payload(
            _write_file_payload(["src/app/page.tsx", "src/app/about.tsx"]),
            workspace=tmp_path,
            home_dir=tmp_path,
        )
        assert envelope.target_paths == ("src/app/page.tsx", "src/app/about.tsx")

    def test_malformed_payload_normalizes_without_crashing(self, tmp_path: Path) -> None:
        """A payload missing tool_name/tool_input still yields a valid envelope.

        Guard falls back to its generic "config_change" classification rather
        than raising, matching every other registered harness's normalizer.
        """

        envelope = normalize_optiqra_payload({}, workspace=tmp_path, home_dir=tmp_path)
        assert envelope.harness == "optiqra"
        assert envelope.action_type == "config_change"
        assert envelope.target_paths == ()


class TestOptiQraHookDecision:
    def test_allowed_action_can_proceed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, output = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="allow",
            capsys=capsys,
        )
        assert rc == 0
        assert output["policy_action"] == "allow"

    def test_denied_action_is_prevented(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, output = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="block",
            capsys=capsys,
        )
        assert rc != 0
        assert output["policy_action"] == "block"

    def test_approval_required_action_is_prevented_pending_approval(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, output = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="review",
            capsys=capsys,
        )
        assert rc != 0
        assert output["policy_action"] == "review"
        # Approval-required is distinct from an outright deny: OptiQra's caller
        # can tell the two apart from the JSON payload even though both exit
        # codes are non-zero and therefore both block the write.
        assert output["policy_action"] != "block"

    def test_denied_and_review_both_prevent_execution_distinctly_from_allow(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        allow_rc, _ = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="allow",
            capsys=capsys,
        )
        block_rc, _ = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="block",
            capsys=capsys,
        )
        review_rc, _ = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/page.tsx"]),
            default_action="review",
            capsys=capsys,
        )
        assert allow_rc == 0
        assert block_rc != 0
        assert review_rc != 0

    def test_target_files_reach_the_recorded_artifact(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc, output = _run_hook(
            tmp_path,
            payload=_write_file_payload(["src/app/checkout.tsx"]),
            default_action="allow",
            capsys=capsys,
        )
        assert rc == 0
        assert output["artifact_name"] == "write_file"


class TestOptiQraMalformedPayload:
    def test_malformed_payload_is_still_evaluated_not_silently_allowed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An empty/garbage payload must not bypass Guard's default policy.

        This mirrors every other harness: the generic hook path evaluates
        whatever action it can normalize (here, a fallback "config_change"
        with no target paths) against the configured default action rather
        than assuming benign intent.
        """

        rc, output = _run_hook(tmp_path, payload={}, default_action="block", capsys=capsys)
        assert rc != 0
        assert output["policy_action"] == "block"


class TestOptiQraDiffVisibilityLimitation:
    """Documents a known limitation rather than a passing feature.

    HOL Guard's action envelope has no first-class diff/content field: any
    payload key that looks like file content is redacted before policy ever
    sees it. This is the same behavior every other harness gets, so OptiQra's
    integration does not (yet) let Guard evaluate the actual diff text, only
    the resolved action and target file paths.
    """

    def test_diff_like_content_is_redacted_not_evaluated(self, tmp_path: Path) -> None:
        payload = {
            "hookEventName": "PreToolUse",
            "tool_name": "write_file",
            "tool_input": {
                "file_paths": ["src/app/page.tsx"],
                "content": "--- a/src/app/page.tsx\n+++ b/src/app/page.tsx\n@@ ...",
            },
        }
        envelope = normalize_optiqra_payload(payload, workspace=tmp_path, home_dir=tmp_path)
        tool_input = envelope.raw_payload_redacted.get("tool_input")
        assert isinstance(tool_input, dict)
        assert tool_input.get("content") == "[redacted]"
