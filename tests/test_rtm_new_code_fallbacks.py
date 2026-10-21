"""Cover resident-fallback and payload-coercion branches added on this branch.

These are the fail-closed paths Sonar marks uncovered: malformed native
payloads, missing capabilities, and digest mismatches must not be treated as
success.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain, native_package_authority, native_package_protect_finalize
from codex_plugin_scanner.guard.approval_gate import (
    _config_from_wire,
    _grant_from_wire,
    input_from_mapping,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import (
    _stamp_runtime_program_digest,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import PackageIntent
from codex_plugin_scanner.guard.runtime.package_request_evaluation import SupplyChainUserCopy

DIGEST = "a" * 64
OTHER = "b" * 64


def _intent_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "package_manager": "npm",
        "intent_kind": "install",
        "redacted_command": "npm install left-pad",
        "targets": [
            {"ecosystem": "npm", "package_name": "left-pad", "raw_spec": "left-pad"},
            "not-a-target",
            {"ecosystem": "", "package_name": "dropped"},
        ],
        "manifest_paths": ["package.json", 1],
        "local_executions": [
            {
                "manager_name": "npm",
                "manager": {"status": "weird", "path": "npm", "resolved_path": 3},
                "manifests": [{"status": "available", "path": "package.json"}, "skip"],
                "typescript_launch": {"status": "unknown", "schema_version": "nope", "reasons": ["x", 1]},
            },
            "skip",
        ],
    }
    payload.update(overrides)
    return payload


def test_package_intent_from_dict_rejects_incomplete_payloads() -> None:
    with pytest.raises(ValueError, match="package_manager"):
        PackageIntent.from_dict({"intent_kind": "install"})
    with pytest.raises(ValueError, match="intent_kind"):
        PackageIntent.from_dict({"package_manager": "npm", "intent_kind": "remove"})


def test_package_intent_from_dict_coerces_malformed_collections() -> None:
    intent = PackageIntent.from_dict(_intent_payload(command_tokens="not-a-list"))
    assert intent.command_tokens == ("npm", "install", "left-pad")
    assert intent.targets[0].package_name == "left-pad"
    assert len(intent.targets) == 1
    assert intent.manifest_paths == ("package.json",)
    execution = intent.local_executions[0]
    assert execution.manager is not None
    assert execution.manager.status == "missing"
    assert execution.manager.resolved_path is None
    assert execution.typescript_launch is not None
    assert execution.typescript_launch.status == "incomplete"
    assert execution.typescript_launch.schema_version == 0
    assert execution.typescript_launch.reasons == ("x",)

    empty = PackageIntent.from_dict(_intent_payload(targets="nope", local_executions=None, manifest_paths=None))
    assert empty.targets == ()
    assert empty.local_executions == ()
    assert empty.manifest_paths == ()


def test_approval_wire_helpers_reject_incomplete_payloads() -> None:
    assert _grant_from_wire(["not", "a", "dict"]) is None
    assert _grant_from_wire({"grant_id": "g"}) is None
    assert _config_from_wire("nope") is None
    assert _config_from_wire({}) is None
    assert input_from_mapping(["nope"]) is None
    parsed = input_from_mapping(
        {
            "approval_password": "secret",
            "approval_gate": {"totp_code": "123456", "current_password": "newer"},
        }
    )
    assert parsed is not None
    assert parsed.password == "newer"
    assert parsed.totp_code == "123456"


def _status(**overrides: object) -> SimpleNamespace:
    identity = SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256=DIGEST)
    capabilities = SimpleNamespace(features=["resident-protocol-v2", "package-authority-v1"])
    status = SimpleNamespace(available=True, compatible=True, identity=identity, capabilities=capabilities)
    for key, value in overrides.items():
        setattr(status, key, value)
    return status


def _patch_authority(monkeypatch: pytest.MonkeyPatch, status: SimpleNamespace, response: bytes | None) -> None:
    monkeypatch.setattr(native_package_authority, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_package_authority, "native_resident_client_request", lambda **_kwargs: response)
    monkeypatch.setattr(native_package_authority, "native_record_resident_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(native_package_authority, "native_record_resident_success", lambda *_args, **_kwargs: None)


def test_package_authority_refuses_unavailable_or_malformed_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    _patch_authority(monkeypatch, _status(available=False), b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(identity=None, capabilities=None), b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    missing = _status()
    missing.capabilities = SimpleNamespace(features=["resident-protocol-v2"])
    _patch_authority(monkeypatch, missing, b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), None)
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b"\xff")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b"[]")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b'{"schema":"other","status":"ok","payload":{}}')
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"error","payload":{}}',
    )
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"ok","payload":["nope"]}',
    )
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    huge = "x" * (256 * 1024 + 1)
    _patch_authority(monkeypatch, _status(), b"{}")
    assert native_package_authority.package_intent_parse_native(huge, guard_home=home) is None


def test_package_intent_parse_requiring_an_answer_raises_without_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    parse = native_package_authority.package_intent_parse_native
    unavailable = native_package_authority.NativePackageIntentUnavailableError
    _patch_authority(monkeypatch, _status(available=False), b"{}")
    with pytest.raises(unavailable, match="native_package_intent_unavailable"):
        parse("npm install left-pad", guard_home=home, require_answer=True)
    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"ok","payload":["nope"]}',
    )
    with pytest.raises(unavailable, match="native_package_intent_malformed"):
        parse("npm install left-pad", guard_home=home, require_answer=True)
    _patch_authority(monkeypatch, _status(), b'{"schema":"guard-package-authority-result.v1","status":"ok"}')
    with pytest.raises(unavailable, match="native_package_intent_malformed"):
        parse("npm install left-pad", guard_home=home, require_answer=True)
    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"ok","payload":null}',
    )
    assert parse("echo hi", guard_home=home, require_answer=True) is None


def test_program_digest_stamp_keeps_snapshot_when_runtime_digests_disagree() -> None:
    extensions = {"program_digest": OTHER, "catalog_digest": DIGEST, "trust_digest": DIGEST}
    assert _stamp_runtime_program_digest(extensions, None) is extensions
    mismatched = SimpleNamespace(program_digest="short", catalog_digest=DIGEST, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, mismatched) is extensions
    catalog_miss = SimpleNamespace(program_digest=DIGEST, catalog_digest=OTHER, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, catalog_miss) is extensions
    already = SimpleNamespace(program_digest=OTHER, catalog_digest=DIGEST, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, already) is extensions
    stamped = _stamp_runtime_program_digest(
        extensions,
        SimpleNamespace(program_digest=DIGEST, catalog_digest=DIGEST, trust_digest=DIGEST),
    )
    assert stamped["program_digest"] == DIGEST
    assert extensions["program_digest"] == OTHER


def _raise_transport(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise RuntimeError("transport")


def test_supply_chain_native_bridge_fails_closed_without_an_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.native_protect_request import NativeProtectRequestError

    monkeypatch.setattr(
        local_supply_chain,
        "_native_package_authority_module",
        lambda: SimpleNamespace(package_intent_parse_native=_raise_transport),
    )
    with pytest.raises(NativeProtectRequestError, match="native_package_intent_unavailable"):
        local_supply_chain._parse_package_intent_native(
            "npm install left-pad",
            environment={"PATH": "/usr/bin"},
            workspace=tmp_path,
            guard_home=tmp_path,
        )
    monkeypatch.setattr(
        local_supply_chain,
        "_native_package_authority_module",
        lambda: SimpleNamespace(package_intent_parse_native=lambda *_args, **_kwargs: {"intent_kind": "nope"}),
    )
    with pytest.raises(NativeProtectRequestError, match="native_package_intent_malformed"):
        local_supply_chain._parse_package_intent_native(
            "npm install left-pad",
            environment=None,
            workspace=tmp_path,
            guard_home=tmp_path,
        )
    calls: list[dict[str, object]] = []

    def _no_intent(*_args: object, **kwargs: object) -> None:
        calls.append(kwargs)
        return None

    monkeypatch.setattr(
        local_supply_chain,
        "_native_package_authority_module",
        lambda: SimpleNamespace(package_intent_parse_native=_no_intent),
    )
    assert (
        local_supply_chain._parse_package_intent_native(
            "echo hi",
            environment=None,
            workspace=tmp_path,
            guard_home=tmp_path,
        )
        is None
    )
    assert calls[0]["require_answer"] is True


def test_package_evaluation_without_resident_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_supply_chain_eval

    monkeypatch.setattr(native_supply_chain_eval, "ensure_resident_prerequisite", lambda _home: False)
    result = local_supply_chain.evaluate_package_request_artifact(
        artifact=SimpleNamespace(
            artifact_id="package:npm:left-pad",
            to_dict=lambda: {"artifact_id": "package:npm:left-pad"},
        ),
        store=SimpleNamespace(guard_home=tmp_path, path=tmp_path / "guard.db", get_cloud_workspace_id=lambda: None),
        workspace_dir=tmp_path,
    )
    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "native_supply_chain_eval_unavailable"


def test_retained_archive_evaluation_without_resident_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_supply_chain_eval

    monkeypatch.setattr(native_supply_chain_eval, "ensure_resident_prerequisite", lambda _home: False)
    result = local_supply_chain.evaluate_package_request_artifact(
        artifact=SimpleNamespace(
            artifact_id="package:npm:left-pad",
            to_dict=lambda: {"artifact_id": "package:npm:left-pad"},
        ),
        store=SimpleNamespace(guard_home=tmp_path, path=tmp_path / "guard.db", get_cloud_workspace_id=lambda: None),
        workspace_dir=tmp_path,
        external_archive_network_authorized=True,
        retain_external_archive_blob=True,
    )
    assert result.decision == "block"
    assert result.reasons[0]["code"] == "native_supply_chain_eval_unavailable"
    assert result.external_archive_downloads == ()


@dataclass(frozen=True)
class _PackageEvaluation:
    policy_action: str = "allow"
    decision: str = "allow"
    reasons: tuple[dict[str, object], ...] = ()
    packages: tuple[dict[str, object], ...] = ({"name": "left-pad", "decision": "allow"},)
    risk_summary: str = ""
    user_copy: SupplyChainUserCopy = field(default_factory=lambda: SupplyChainUserCopy("t", "s", None, None, "h"))
    record_monitor_evidence: bool = True


@pytest.mark.parametrize("resident_down", (True, False))
def test_unclaimed_saved_package_approval_is_dropped_without_a_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resident_down: bool
) -> None:
    current = SimpleNamespace(
        artifact=SimpleNamespace(artifact_id="package:npm:left-pad"),
        artifact_hash="hash",
        evaluation=_PackageEvaluation(),
        current_action="allow",
        execution_context=None,
        observe_mode=False,
        additional_current_action=None,
        additional_policy_context=None,
        invoking_harness=None,
    )
    stored = {"decision": {"action": "allow"}, "ignored_integrity": False, "daemon_authority": False}
    monkeypatch.setattr(local_supply_chain, "_build_package_protect_authority", lambda **_kwargs: current)
    monkeypatch.setattr(local_supply_chain, "_package_policy_workspace_candidates", lambda **_kwargs: ("/w",))
    monkeypatch.setattr(local_supply_chain, "package_protect_stored_policy", lambda *_args, **_kwargs: stored)
    # Down, or up but older than the op (missing feature, timeout): both fail closed.
    monkeypatch.setattr(
        native_package_protect_finalize, "ensure_resident_prerequisite", lambda _home: not resident_down
    )
    monkeypatch.setattr(native_package_protect_finalize, "_resident_request", lambda **_kwargs: None)

    authority, result = local_supply_chain._final_package_protect_authority(
        initial=current,
        initial_saved_evaluation=None,
        saved_approval_pending=False,
        command=["npm", "install", "left-pad"],
        store=SimpleNamespace(guard_home=tmp_path),
        workspace_dir=tmp_path,
        now="2026-10-15T00:00:00Z",
        config=None,
        current_config_provider=None,
        additional_authority_provider=None,
    )

    assert authority is current
    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "native_package_evaluation_unavailable"
    assert all(package["decision"] == "block" for package in result.packages)


_VERDICT = {
    "decision": "allow",
    "risk_summary": "",
    "user_copy": {"title": "t", "summary": "s", "next_step": None, "dashboard_url": None, "headline": "h"},
    "record_monitor_evidence": False,
}


@pytest.mark.parametrize(
    ("current_action", "observe_mode", "claim_failed", "with_current", "patch"),
    (
        # A fixed current action (claim failed, observe mode) cannot be rewritten.
        ("block", False, True, True, {"policy_action": "allow", **_VERDICT}),
        ("review", True, False, True, {"policy_action": "allow", **_VERDICT}),
        # No rebuilt authority: the reply can only reject the reuse.
        ("block", False, False, False, {"policy_action": "allow", **_VERDICT}),
        ("block", False, False, False, {"policy_action": "warn", **_VERDICT}),
        # An action change must carry its verdict.
        ("allow", False, False, True, {"policy_action": "allow"}),
        # Only a claimed approval may be reused.
        ("block", False, False, True, {"reasons": [{"code": "saved_package_approval"}]}),
        # ...including one the reply leaves in place from the base evaluation.
        ("block", False, False, True, {}),
    ),
)
def test_package_protect_finalize_rejects_replies_breaking_request_invariants(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    current_action: str,
    observe_mode: bool,
    claim_failed: bool,
    with_current: bool,
    patch: dict[str, object],
) -> None:
    blocked = _PackageEvaluation(
        policy_action="block",
        decision="block",
        reasons=({"code": "saved_package_approval"},) if not patch else (),
    )
    initial = SimpleNamespace(
        artifact=SimpleNamespace(artifact_id="package:npm:left-pad"), artifact_hash="hash", evaluation=blocked
    )
    current = SimpleNamespace(
        artifact=initial.artifact,
        artifact_hash="hash",
        evaluation=blocked,
        current_action=current_action,
        observe_mode=observe_mode,
    )
    monkeypatch.setattr(native_package_protect_finalize, "_call", lambda _request, _home: dict(patch))

    with pytest.raises(native_package_protect_finalize.NativePackageProtectFinalizeError):
        native_package_protect_finalize.native_finalize_package_protect(
            initial=initial,
            current=current if with_current else None,
            claim_failure=blocked if claim_failed else None,
            saved_approval_claimed=False,
            claim_disposition=None,
            stored_policy=None,
            store=SimpleNamespace(guard_home=tmp_path),
        )
