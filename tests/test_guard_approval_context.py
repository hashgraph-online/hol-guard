from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import approval_context as approval_context_module
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    NativeContextDigestUnavailableError,
    approval_context_token_is_well_formed,
    approval_context_tokens_validation_reason,
    build_approval_context_token,
    build_runtime_executable_identity,
    build_runtime_launch_identity,
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


def _decoded_payload(token: str) -> dict[str, object]:
    """Decode a minted token here so the assertions can name its components.

    Guard itself no longer decodes a token in Python — the native authority
    owns the grammar — but these tests have to look inside one to show what it
    does and does not carry, so the decode lives with the assertions that need
    it rather than in the runtime.
    """

    encoded = token[len(APPROVAL_CONTEXT_TOKEN_PREFIX) :]
    raw = base64.urlsafe_b64decode(f"{encoded}{'=' * (-len(encoded) % 4)}".encode("ascii"))
    payload = json.loads(raw.decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_token_is_deterministic_for_equivalent_structured_context(native_context_digest: Path) -> None:
    first = _token(
        identity={"workspace": "/private/workspace", "artifact_id": "codex:project:tool:read"},
        sandbox={"network": False, "mode": "workspace-write"},
    )
    second = _token()

    assert first == second
    assert first.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert approval_context_token_is_well_formed(first)


def test_runtime_launch_resolves_current_user_tilde_from_trusted_home(tmp_path) -> None:
    executable = tmp_path / "bin" / "reviewed-commit"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    identity = build_runtime_launch_identity(
        "~/bin/reviewed-commit --message test",
        cwd=tmp_path,
        home_dir=tmp_path,
        launch_env={"PATH": ""},
    )
    executable_identity = identity["executable"]

    assert isinstance(executable_identity, dict)
    assert executable_identity["status"] == "verified"
    assert executable_identity["path"] == str(executable.resolve())


def test_runtime_launch_keeps_repeated_tilde_separators_inside_trusted_home(tmp_path) -> None:
    executable = tmp_path / "bin" / "reviewed-commit"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    identity = build_runtime_launch_identity(
        "~//bin/reviewed-commit --message test",
        cwd=tmp_path,
        home_dir=tmp_path,
        launch_env={"PATH": ""},
    )
    executable_identity = identity["executable"]

    assert isinstance(executable_identity, dict)
    assert executable_identity["status"] == "verified"
    assert executable_identity["path"] == str(executable.resolve())


@pytest.mark.parametrize(
    "command",
    ('"~/bin/reviewed-commit"', "\\~/bin/reviewed-commit", "~\\/bin/reviewed-commit", '~""/bin/reviewed-commit'),
)
def test_runtime_launch_rejects_non_expanding_tilde_syntax(command: str, tmp_path) -> None:
    identity = build_runtime_launch_identity(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        launch_env={"PATH": ""},
    )
    executable_identity = identity["executable"]

    assert isinstance(executable_identity, dict)
    assert executable_identity["status"] == "ambiguous_tilde_syntax"
    assert isinstance(executable_identity["reuse_nonce"], str)


@pytest.mark.parametrize(
    ("command", "expected_status"),
    (
        ("~/bin/reviewed-commit", "unresolved_home"),
        ("~other/bin/reviewed-commit", "ambiguous_tilde_syntax"),
        ("~/C:/bin/reviewed-commit", "unresolved_home"),
    ),
)
def test_runtime_launch_without_matching_trusted_home_fails_closed(
    command: str,
    expected_status: str,
    tmp_path: Path,
) -> None:
    identity = build_runtime_launch_identity(
        command,
        cwd=tmp_path,
        home_dir=None,
        launch_env={"PATH": ""},
    )
    executable_identity = identity["executable"]

    assert isinstance(executable_identity, dict)
    assert executable_identity["status"] == expected_status
    assert isinstance(executable_identity["reuse_nonce"], str)


def test_token_serializes_only_component_hashes_and_not_source_values(native_context_digest: Path) -> None:
    source_values = (
        "codex:project:tool:read",
        "/private/workspace",
        "artifact-hash:arbitrary:text",
        "filesystem:read",
        "private-policy-fingerprint",
        "workspace-write",
    )
    token = _token()
    payload = _decoded_payload(token)

    assert approval_context_token_is_well_formed(token)
    assert all(source not in token for source in source_values)
    assert set(payload) == {"version", "identity", "content", "capabilities", "policy", "sandbox"}
    assert all(
        isinstance(component_hash, str)
        and len(component_hash) == 64
        and component_hash.isascii()
        and component_hash.isalnum()
        for key, component_hash in payload.items()
        if key != "version"
    )


def test_opaque_token_comparison_accepts_unchanged_context(native_context_digest: Path) -> None:
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
def test_legacy_or_malformed_saved_value_fails_closed_as_changed_content(
    legacy_or_malformed: object, native_context_digest: Path
) -> None:
    assert approval_context_tokens_validation_reason(legacy_or_malformed, _token()) == "approval_reuse_content_changed"


def test_even_equal_legacy_values_cannot_prove_structured_context_is_unchanged(native_context_digest: Path) -> None:
    assert (
        approval_context_tokens_validation_reason("sha256:legacy", "sha256:legacy") == "approval_reuse_content_changed"
    )


def test_token_with_an_extra_payload_field_is_not_well_formed(native_context_digest: Path) -> None:
    payload = dict(_decoded_payload(_token()))
    payload["raw_secret"] = "must-not-be-accepted"

    assert not approval_context_token_is_well_formed(f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{_encoded_payload(payload)}")


@pytest.mark.parametrize(
    "legacy_or_malformed",
    (
        None,
        object(),
        "",
        "sha256:legacy-artifact-hash",
        f"{APPROVAL_CONTEXT_TOKEN_PREFIX}not+base64url",
        f"{APPROVAL_CONTEXT_TOKEN_PREFIX}{_encoded_payload({'version': 2})}",
    ),
)
def test_only_a_minted_token_is_well_formed(legacy_or_malformed: object, native_context_digest: Path) -> None:
    assert approval_context_token_is_well_formed(_token())
    assert not approval_context_token_is_well_formed(legacy_or_malformed)


@pytest.mark.parametrize(
    "failure",
    (NativeContextDigestUnavailableError("unreachable"), TypeError("rejected input")),
)
def test_token_is_not_well_formed_when_the_native_authority_cannot_answer(
    failure: Exception, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """A verdict Guard cannot obtain is not a token where reuse depends on it.

    The stored approval key falls back to the exact-command form, and saved
    evidence is treated as legacy rather than as a context binding, so those
    callers get ``False``. A harness or global policy row is the exception:
    it drops a hash that is not a token, so the policy-key site keeps any
    prefixed value rather than widening the row to the artifact family.
    """

    from codex_plugin_scanner.guard.store_base import _is_approval_context_token

    token = _token()

    def _unavailable(kind: str, fields: dict[str, object]) -> dict[str, object]:
        raise failure

    monkeypatch.setattr(approval_context_module, "_context_digest_result", _unavailable)

    assert not approval_context_token_is_well_formed(token)
    assert _is_approval_context_token(token)
    assert not _is_approval_context_token("sha256:legacy")


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
