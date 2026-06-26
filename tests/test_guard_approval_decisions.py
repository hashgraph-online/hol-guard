"""Approval decision model tests — P2.4.

Covers:
- Unchanged artifact → stored allow policy → no reapproval triggered
- Changed artifact hash → require-reapproval via decide_action
- Changed capability → require-reapproval via decide_action
- Scope persistence for artifact/workspace/publisher/harness/global scopes
- Receipt field completeness from build_receipt
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash as compute_artifact_hash
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from codex_plugin_scanner.guard.policy.engine import decide_action
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore


def _make_artifact(
    artifact_id: str = "codex:project:my_tool",
    command: str = "python",
    args: tuple[str, ...] = ("-m", "my_tool"),
    publisher: str | None = None,
) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name="my_tool",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/home/user/.codex/config.toml",
        command=command,
        args=args,
        transport="stdio",
        publisher=publisher,
    )


def _make_config(tmp_path: Path, default_action: str = "require-reapproval") -> GuardConfig:
    return GuardConfig(
        guard_home=tmp_path / "guard",
        workspace=tmp_path / "workspace",
        default_action=default_action,
    )


def _make_store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard")


def test_resolve_policy_without_matching_rules_skips_policy_integrity_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _make_store(tmp_path)

    def fail_refresh(*_args, **_kwargs):
        raise AssertionError("policy integrity refresh should not run for an empty policy lookup")

    monkeypatch.setattr(store, "_refresh_policy_integrity_state", fail_refresh)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", fail_refresh)

    assert store.resolve_policy("codex", "codex:project:none", "hash-none") is None


def test_resolve_policy_with_remote_only_rule_skips_policy_integrity_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _make_store(tmp_path)
    artifact_id = "codex:project:remote-only"
    artifact_hash = "hash-remote"
    store.replace_remote_policies(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                workspace=None,
                publisher=None,
                action="allow",
                reason="remote policy",
                owner=None,
                source="cloud-sync",
            )
        ],
        now="2026-06-26T00:00:00Z",
        remote_write_authorized=True,
    )

    def fail_refresh(*_args, **_kwargs):
        raise AssertionError("policy integrity refresh should not run for remote-only policy lookups")

    monkeypatch.setattr(store, "_refresh_policy_integrity_state", fail_refresh)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", fail_refresh)

    assert store.resolve_policy("codex", artifact_id, artifact_hash) == "allow"


class TestDecideAction:
    def test_allow_policy_passes_through_unchanged(self) -> None:
        config = GuardConfig(guard_home=Path("/tmp/test-guard"), workspace=None)
        result = decide_action(
            configured_action="allow",
            default_action="require-reapproval",
            config=config,
            changed=False,
        )
        assert result == "allow"

    def test_changed_triggers_changed_hash_action_when_no_configured_policy(self) -> None:
        config = GuardConfig(
            guard_home=Path("/tmp/test-guard"),
            workspace=None,
            changed_hash_action="require-reapproval",
        )
        result = decide_action(
            configured_action=None,
            default_action="allow",
            config=config,
            changed=True,
        )
        assert result == "require-reapproval"

    def test_configured_allow_beats_changed_flag(self) -> None:
        config = GuardConfig(
            guard_home=Path("/tmp/test-guard"),
            workspace=None,
            changed_hash_action="require-reapproval",
        )
        result = decide_action(
            configured_action="allow",
            default_action="allow",
            config=config,
            changed=True,
        )
        assert result == "allow"

    def test_changed_falls_back_to_safe_when_no_changed_hash_action(self) -> None:
        config = GuardConfig(guard_home=Path("/tmp/test-guard"), workspace=None)
        result = decide_action(
            configured_action=None,
            default_action=None,
            config=config,
            changed=True,
        )
        assert result == "require-reapproval"

    def test_block_policy_blocks_regardless_of_changed_flag(self) -> None:
        config = GuardConfig(guard_home=Path("/tmp/test-guard"), workspace=None)
        result = decide_action(
            configured_action="block",
            default_action="allow",
            config=config,
            changed=False,
        )
        assert result == "block"

    def test_no_policy_uses_config_default(self) -> None:
        config = GuardConfig(
            guard_home=Path("/tmp/test-guard"),
            workspace=None,
            default_action="warn",
        )
        result = decide_action(
            configured_action=None,
            default_action=None,
            config=config,
            changed=False,
        )
        assert result == "warn"

    def test_explicit_default_action_overrides_config(self) -> None:
        config = GuardConfig(
            guard_home=Path("/tmp/test-guard"),
            workspace=None,
            default_action="warn",
        )
        result = decide_action(
            configured_action=None,
            default_action="allow",
            config=config,
            changed=False,
        )
        assert result == "allow"


class TestPolicyScopePersistence:
    def test_artifact_scope_allow_resolves_for_matching_hash(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:my_tool",
                artifact_hash="abc123",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:my_tool", "abc123")
        assert result == "allow"

    def test_artifact_scope_allow_resolves_without_hash_when_policy_has_no_hash(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:my_tool",
                artifact_hash=None,
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:my_tool", "any-hash")
        assert result == "allow"

    def test_publisher_scope_resolves_for_any_artifact_by_publisher(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="publisher",
                action="allow",
                publisher="verified-org",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:any_tool", "hash-x", publisher="verified-org")
        assert result == "allow"

    def test_publisher_scope_does_not_match_different_publisher(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="publisher",
                action="allow",
                publisher="verified-org",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:any_tool", "hash-x", publisher="unknown-org")
        assert result is None

    def test_harness_scope_resolves_for_all_artifacts_in_harness(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="allow",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:any_tool", "hash-y")
        assert result == "allow"

    def test_harness_unsupported_family_is_rejected_without_policy_row(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        with pytest.raises(ValueError, match="unsupported_scoped_policy_family"):
            store.upsert_policy(
                PolicyDecision(
                    harness="codex",
                    scope="harness",
                    action="allow",
                    artifact_id="family:tool-output",
                ),
                "2026-01-01T00:00:00+00:00",
            )
        assert store.list_policy_decisions("codex") == []
        for artifact_id in (
            "codex:project:tool-output:stdout",
            "codex:project:tool-action:run-shell",
            "codex:project:file-read:.npmrc",
        ):
            assert store.resolve_policy("codex", artifact_id, "hash") is None

    def test_global_scope_resolves_for_any_harness(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="global",
                action="block",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:anything", "hash-z")
        assert result == "block"

    def test_artifact_scope_takes_precedence_over_global_scope(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="global",
                action="block",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:trusted_tool",
                artifact_hash=None,
            ),
            "2026-01-01T00:00:00+00:00",
        )
        result = store.resolve_policy("codex", "codex:project:trusted_tool", "any-hash")
        assert result == "allow"

    def test_expired_policy_is_not_matched(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="codex:project:my_tool",
                artifact_hash=None,
                expires_at="2025-01-01T00:00:00+00:00",
            ),
            "2024-12-01T00:00:00+00:00",
        )
        result = store.resolve_policy(
            "codex",
            "codex:project:my_tool",
            "hash-abc",
            now="2026-01-01T00:00:00+00:00",
        )
        assert result is None


class TestEvaluateDetectionScopePersistence:
    def test_unchanged_artifact_with_stored_allow_policy_is_not_blocked(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        config = _make_config(tmp_path)
        artifact = _make_artifact()

        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id=artifact.artifact_id,
                artifact_hash=None,
            ),
            "2026-01-01T00:00:00+00:00",
        )

        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        result = evaluate_detection(detection, store, config, persist=False)

        artifact_result = result["artifacts"][0]
        assert artifact_result["policy_action"] == "allow"
        assert result["blocked"] is False

    def test_changed_artifact_hash_without_stored_policy_triggers_reapproval(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        config = _make_config(tmp_path)
        artifact_v1 = _make_artifact(args=("-m", "my_tool", "--port", "8000"))
        artifact_v2 = _make_artifact(args=("-m", "my_tool", "--port", "9000"))

        detection_v1 = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact_v1.config_path,),
            artifacts=(artifact_v1,),
        )
        evaluate_detection(detection_v1, store, config, persist=True)

        detection_v2 = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact_v2.config_path,),
            artifacts=(artifact_v2,),
        )
        result = evaluate_detection(detection_v2, store, config, persist=False)

        artifact_result = result["artifacts"][0]
        assert artifact_result["policy_action"] in {"require-reapproval", "block", "sandbox-required"}
        assert result["blocked"] is True

    def test_hash_locked_policy_does_not_match_new_hash_triggers_reapproval(self, tmp_path: Path) -> None:
        store = _make_store(tmp_path)
        config = _make_config(tmp_path, default_action="allow")
        artifact_v1 = _make_artifact(args=("-m", "my_tool", "--port", "8000"))
        artifact_v2 = _make_artifact(args=("-m", "my_tool", "--port", "9999"))

        v1_hash = compute_artifact_hash(artifact_v1)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id=artifact_v1.artifact_id,
                artifact_hash=v1_hash,
            ),
            "2026-01-01T00:00:00+00:00",
        )

        detection_v1 = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact_v1.config_path,),
            artifacts=(artifact_v1,),
        )
        evaluate_detection(detection_v1, store, config, persist=True)

        detection_v2 = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact_v2.config_path,),
            artifacts=(artifact_v2,),
        )
        result = evaluate_detection(detection_v2, store, config, persist=False)

        artifact_result = result["artifacts"][0]
        assert artifact_result["policy_action"] in {"require-reapproval", "block", "sandbox-required"}
        assert result["blocked"] is True


class TestBuildReceipt:
    def test_build_receipt_populates_required_fields(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:my_tool",
            artifact_hash="sha256-abc",
            policy_decision="allow",
            capabilities_summary="command: python",
            changed_capabilities=[],
            provenance_summary="project artifact at /workspace/.codex/config.toml (provenance: local)",
            artifact_name="my_tool",
            source_scope="project",
        )

        assert receipt.receipt_id.startswith("guard-receipt-")
        assert receipt.harness == "codex"
        assert receipt.artifact_id == "codex:project:my_tool"
        assert receipt.artifact_hash == "sha256-abc"
        assert receipt.policy_decision == "allow"
        assert receipt.capabilities_summary == "command: python"
        assert receipt.changed_capabilities == ()
        assert "project artifact" in receipt.provenance_summary
        assert receipt.artifact_name == "my_tool"
        assert receipt.source_scope == "project"
        assert receipt.timestamp != ""

    def test_build_receipt_changed_capabilities_are_stored_as_tuple(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:my_tool",
            artifact_hash="sha256-abc",
            policy_decision="require-reapproval",
            capabilities_summary="command: python",
            changed_capabilities=["args", "command"],
            provenance_summary="project artifact",
            artifact_name="my_tool",
            source_scope="project",
        )
        assert receipt.changed_capabilities == ("args", "command")

    def test_build_receipt_user_override_defaults_to_none(self) -> None:
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:my_tool",
            artifact_hash="hash",
            policy_decision="allow",
            capabilities_summary="",
            changed_capabilities=[],
            provenance_summary="provenance",
            artifact_name=None,
            source_scope=None,
        )
        assert receipt.user_override is None

    def test_build_receipt_to_dict_serializes_scanner_evidence(self) -> None:
        evidence = [{"type": "scan", "finding": "clean"}]
        receipt = build_receipt(
            harness="codex",
            artifact_id="codex:project:my_tool",
            artifact_hash="hash",
            policy_decision="allow",
            capabilities_summary="",
            changed_capabilities=[],
            provenance_summary="provenance",
            artifact_name=None,
            source_scope=None,
            scanner_evidence=evidence,
        )
        d = receipt.to_dict()
        assert isinstance(d["scanner_evidence"], list)
        assert d["scanner_evidence"][0]["type"] == "scan"

    def test_build_receipt_generates_unique_receipt_ids(self) -> None:
        receipts = [
            build_receipt(
                harness="codex",
                artifact_id=f"codex:project:tool_{i}",
                artifact_hash="hash",
                policy_decision="allow",
                capabilities_summary="",
                changed_capabilities=[],
                provenance_summary="provenance",
                artifact_name=None,
                source_scope=None,
            )
            for i in range(5)
        ]
        ids = {r.receipt_id for r in receipts}
        assert len(ids) == 5, "Each receipt must have a unique receipt_id"
