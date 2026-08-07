from __future__ import annotations

import base64
import json
import os

import pytest

from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    ApprovalContextToken,
    approval_context_tokens_validation_reason,
    approval_context_validation_reason,
    build_approval_context_token,
    build_runtime_executable_identity,
    parse_approval_context_token,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)


def _context(**overrides: object) -> dict[str, object]:
    context: dict[str, object] = {
        "identity": {"artifact_id": "codex:project:tool:read", "workspace": "/private/workspace"},
        "content": "artifact-hash:arbitrary:text",
        "capabilities": ["filesystem:read", "network:none"],
        "policy": {"action": "review", "fingerprint": "private-policy-fingerprint"},
        "sandbox": {"mode": "workspace-write", "network": False},
    }
    context.update(overrides)
    return context


def _token(**overrides: object) -> str:
    return build_approval_context_token(**_context(**overrides))


def _encoded_payload(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_token_is_deterministic_for_equivalent_structured_context() -> None:
    first = _token(
        identity={"workspace": "/private/workspace", "artifact_id": "codex:project:tool:read"},
        sandbox={"network": False, "mode": "workspace-write"},
    )
    second = _token()

    assert first == second
    assert first.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert parse_approval_context_token(first) == parse_approval_context_token(second)


def test_token_serializes_only_component_hashes_and_not_source_values() -> None:
    source_values = (
        "codex:project:tool:read",
        "/private/workspace",
        "artifact-hash:arbitrary:text",
        "filesystem:read",
        "private-policy-fingerprint",
        "workspace-write",
    )
    token = _token()
    parsed = parse_approval_context_token(token)

    assert parsed is not None
    assert all(source not in token for source in source_values)
    assert all(
        len(component_hash) == 64 and component_hash.isascii() and component_hash.isalnum()
        for component_hash in (
            parsed.identity_hash,
            parsed.content_hash,
            parsed.capabilities_hash,
            parsed.policy_hash,
            parsed.sandbox_hash,
        )
    )


def test_token_is_invalidated_when_extension_control_snapshot_changes() -> None:
    first_snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, "a" * 64, ())
    )
    second_snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 2, "a" * 64, ())
    )

    with use_extension_control_snapshot(first_snapshot):
        saved = _token()
    with use_extension_control_snapshot(second_snapshot):
        current = _token()

    assert saved != current
    assert approval_context_tokens_validation_reason(saved, current) == "approval_reuse_policy_changed"


def test_arbitrary_artifact_hash_text_is_bound_without_interpretation() -> None:
    artifact_hash = "not-sha256:guard-approval-context:v1:\n☃\x00"
    saved = _token(content=artifact_hash)

    assert approval_context_validation_reason(saved, **_context(content=artifact_hash)) is None
    assert (
        approval_context_validation_reason(saved, **_context(content=f"{artifact_hash}:changed"))
        == "approval_reuse_content_changed"
    )


@pytest.mark.parametrize(
    ("changed_context", "expected_reason"),
    (
        ({"identity": {"artifact_id": "different"}}, "approval_reuse_identity_changed"),
        ({"content": "changed-content"}, "approval_reuse_content_changed"),
        ({"capabilities": ["filesystem:read", "network:egress"]}, "approval_reuse_capability_changed"),
        ({"policy": {"action": "block"}}, "approval_reuse_policy_changed"),
        ({"sandbox": {"mode": "host", "network": True}}, "approval_reuse_sandbox_changed"),
    ),
)
def test_validator_reports_stable_changed_dimension(
    changed_context: dict[str, object],
    expected_reason: str,
) -> None:
    saved = _token()

    assert approval_context_validation_reason(saved, **_context(**changed_context)) == expected_reason


def test_validator_uses_stable_security_precedence_when_multiple_dimensions_change() -> None:
    saved = _token()

    assert (
        approval_context_validation_reason(
            saved,
            **_context(identity="changed", content="changed", policy="changed", sandbox="changed"),
        )
        == "approval_reuse_identity_changed"
    )


def test_opaque_token_comparison_accepts_unchanged_context() -> None:
    saved = _token()
    current = _token()

    assert approval_context_tokens_validation_reason(saved, current) is None


@pytest.mark.parametrize(
    "legacy_or_malformed",
    (
        None,
        "sha256:legacy-artifact-hash",
        "",
        f"{APPROVAL_CONTEXT_TOKEN_PREFIX}not+base64url",
        f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{_encoded_payload({'version': 2})}",
        f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{_encoded_payload({'version': 1, 'identity': '0' * 64})}",
    ),
)
def test_legacy_or_malformed_saved_value_fails_closed_as_changed_content(legacy_or_malformed: object) -> None:
    assert approval_context_tokens_validation_reason(legacy_or_malformed, _token()) == "approval_reuse_content_changed"


def test_even_equal_legacy_values_cannot_prove_structured_context_is_unchanged() -> None:
    assert (
        approval_context_tokens_validation_reason("sha256:legacy", "sha256:legacy") == "approval_reuse_content_changed"
    )


def test_parser_rejects_payload_with_unexpected_fields() -> None:
    parsed = parse_approval_context_token(_token())
    assert isinstance(parsed, ApprovalContextToken)
    payload = {
        "version": 1,
        "identity": parsed.identity_hash,
        "content": parsed.content_hash,
        "capabilities": parsed.capabilities_hash,
        "policy": parsed.policy_hash,
        "sandbox": parsed.sandbox_hash,
        "raw_secret": "must-not-be-accepted",
    }

    assert parse_approval_context_token(f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{_encoded_payload(payload)}") is None


def test_builder_rejects_non_json_context_without_leaking_its_value() -> None:
    class Unsupported:
        def __repr__(self) -> str:
            return "very-private-value"

    with pytest.raises(TypeError, match="component 'identity' must be JSON-compatible") as exc_info:
        _token(identity=Unsupported())

    assert "very-private-value" not in str(exc_info.value)


def test_runtime_executable_identity_changes_after_same_path_byte_replacement(tmp_path) -> None:
    executable = tmp_path / "guard-tool"
    executable.write_bytes(b"#!/bin/sh\necho first\n")
    executable.chmod(0o755)
    first = build_runtime_executable_identity(str(executable))

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"#!/bin/sh\necho other\n")
    replacement.chmod(0o755)
    os.replace(replacement, executable)
    second = build_runtime_executable_identity(str(executable))

    assert first["status"] == second["status"] == "verified"
    assert first["path"] == second["path"] == str(executable.resolve())
    assert first["size"] == second["size"]
    assert first["sha256"] != second["sha256"]
    assert first != second


def test_runtime_executable_identity_binds_security_relevant_mode(tmp_path) -> None:
    executable = tmp_path / "guard-tool"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    executable_identity = build_runtime_executable_identity(str(executable))

    executable.chmod(0o700)
    restricted_identity = build_runtime_executable_identity(str(executable))

    assert executable_identity["sha256"] == restricted_identity["sha256"]
    assert executable_identity["mode"] == 0o755
    assert restricted_identity["mode"] == 0o700
    assert executable_identity != restricted_identity


def test_runtime_executable_identity_binds_resolved_symlink_target(tmp_path) -> None:
    first_target = tmp_path / "guard-tool-v1"
    second_target = tmp_path / "guard-tool-v2"
    first_target.write_bytes(b"#!/bin/sh\necho v1\n")
    second_target.write_bytes(b"#!/bin/sh\necho v2\n")
    first_target.chmod(0o755)
    second_target.chmod(0o755)
    executable_link = tmp_path / "guard-tool"
    executable_link.symlink_to(first_target.name)
    first = build_runtime_executable_identity(str(executable_link))

    executable_link.unlink()
    executable_link.symlink_to(second_target.name)
    second = build_runtime_executable_identity(str(executable_link))

    assert first["path"] == str(first_target.resolve())
    assert second["path"] == str(second_target.resolve())
    assert first["sha256"] != second["sha256"]
    assert first != second


def test_runtime_executable_identity_resolves_relative_path_from_launch_cwd(tmp_path) -> None:
    guard_cwd = tmp_path / "guard-process"
    launch_cwd = tmp_path / "runtime-workspace"
    guard_cwd.mkdir()
    launch_cwd.mkdir()
    guard_executable = guard_cwd / "server"
    runtime_executable = launch_cwd / "server"
    guard_executable.write_bytes(b"#!/bin/sh\necho guard-process\n")
    runtime_executable.write_bytes(b"#!/bin/sh\necho runtime-workspace\n")
    guard_executable.chmod(0o755)
    runtime_executable.chmod(0o755)

    identity = build_runtime_executable_identity("./server", cwd=launch_cwd)

    assert identity["status"] == "verified"
    assert identity["path"] == str(runtime_executable.resolve())
    assert identity["launch_cwd"] == str(launch_cwd.resolve())
    assert identity["sha256"] != build_runtime_executable_identity(str(guard_executable))["sha256"]
