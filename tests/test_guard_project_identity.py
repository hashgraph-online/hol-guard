from __future__ import annotations

import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.policy_bundle_decisions import build_policy_bundle_decisions
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.project_identity import (
    enrich_project_identity_metadata,
    is_portable_project_identity,
    resolve_portable_project_identity,
    resolve_project_identity_from_metadata,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle

_NOW = "2026-08-07T20:00:00+00:00"
_WORKSPACE_ID = "workspace-solo-project-memory"


def _git(workspace: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(workspace), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def _mark_clone_provenance(workspace: Path, remote: str) -> None:
    """Make the fixture model Git's initial clone reflog without network access."""
    head_log = workspace / ".git" / "logs" / "HEAD"
    lines = head_log.read_text(encoding="utf-8").splitlines()
    assert lines
    metadata, separator, _message = lines[0].partition("\t")
    assert separator
    lines[0] = f"{metadata}\tclone: from {remote}"
    head_log.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _init_repository(workspace: Path, remote: str, *, verified_clone: bool = True) -> None:
    workspace.mkdir(parents=True)
    _git(workspace, "init")
    _git(workspace, "config", "user.email", "guard@example.invalid")
    _git(workspace, "config", "user.name", "Guard Test")
    (workspace / "README.md").write_text("guard\n", encoding="utf-8")
    _git(workspace, "add", "README.md")
    _git(workspace, "commit", "-m", "initial")
    _git(workspace, "remote", "add", "origin", remote)
    if verified_clone:
        _mark_clone_provenance(workspace, remote)


def _bind_cloud_workspace(store: GuardStore) -> None:
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="project-memory-test-refresh-token",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        workspace_id=_WORKSPACE_ID,
        now=_NOW,
    )


def _record_project_operation(store: GuardStore, workspace: Path) -> dict[str, object]:
    store.upsert_guard_session(
        session_id="session-a",
        harness="codex",
        surface="cli",
        status="active",
        client_name="codex",
        client_title=None,
        client_version="test",
        workspace=str(workspace),
        capabilities=[],
        now=_NOW,
    )
    store.upsert_guard_operation(
        operation_id="operation-a",
        session_id="session-a",
        harness="codex",
        operation_type="tool_action",
        status="pending",
        approval_request_ids=["request-a"],
        resume_token=None,
        metadata={"workspace_path": str(workspace)},
        now=_NOW,
    )
    operation = store.get_guard_operation_for_approval_request("request-a")
    assert operation is not None
    return operation


def _signed_project_memory_bundle(
    *rules: tuple[str, str, str],
) -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-08-07.1",
            "bundleHash": "",
            "issuedAt": _NOW,
            "expiresAt": None,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": "test-only-placeholder",
                "signature": None,
            },
            "rolloutState": "enforcing",
            "policyDefaults": {
                "mode": "prompt",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [
                {
                    "ruleId": rule_id,
                    "action": action,
                    "reason": f"Project memory test rule {rule_id}.",
                    "artifactId": "tool:read",
                    "scope": {
                        "agents": [],
                        "devices": [],
                        "ecosystems": [],
                        "environments": [],
                        "harnesses": ["codex"],
                        "locations": [project_scope],
                    },
                }
                for rule_id, action, project_scope in rules
            ],
            "cloudExceptions": [],
            "acknowledgements": [],
        },
        workspace_id=_WORKSPACE_ID,
    )


def _activate_project_memory_bundle(
    store: GuardStore,
    bundle: dict[str, object],
) -> None:
    _bind_cloud_workspace(store)
    device = store.get_device_metadata()
    applied = store.apply_policy_bundle_authority(
        build_policy_bundle_decisions(
            bundle,
            device_id=str(device["installation_id"]),
            device_name=str(device["device_label"]),
        ),
        _NOW,
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
        cloud_exceptions=[],
        policy_bundle_ack={
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "deviceId": device["installation_id"],
            "status": "synced",
        },
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert applied is True


def test_portable_project_identity_matches_across_clone_locations(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    first = tmp_path / "first" / "repo"
    second = tmp_path / "second" / "repo"
    other_port = tmp_path / "other-port" / "repo"
    implicit_default = tmp_path / "implicit-default" / "repo"
    explicit_default = tmp_path / "explicit-default" / "repo"
    remote = "ssh://git@example.invalid:2201/owner/repository.git"
    _init_repository(first, remote)
    _init_repository(second, remote)
    _init_repository(other_port, "ssh://git@example.invalid:2202/owner/repository.git")
    _init_repository(implicit_default, "https://github.com/Owner/Repository.git")
    _init_repository(explicit_default, "https://github.com:443/owner/repository.GIT")

    def reject_subprocess(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("Portable project identity must not launch a subprocess")

    monkeypatch.setattr(subprocess, "run", reject_subprocess)
    first_identity = resolve_portable_project_identity(first)
    second_identity = resolve_portable_project_identity(second)
    other_port_identity = resolve_portable_project_identity(other_port)
    implicit_default_identity = resolve_portable_project_identity(implicit_default)
    explicit_default_identity = resolve_portable_project_identity(explicit_default)

    assert first_identity is not None
    assert first_identity == second_identity
    assert first_identity != other_port_identity
    assert implicit_default_identity == explicit_default_identity
    assert is_portable_project_identity(first_identity)
    assert str(first) not in first_identity
    assert str(second) not in second_identity


def test_spoofed_origin_without_clone_provenance_cannot_claim_portable_identity(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted" / "repo"
    unrelated = tmp_path / "unrelated" / "repo"
    remote = "https://github.com/example/trusted-repository.git"
    _init_repository(trusted, remote)
    _init_repository(unrelated, remote, verified_clone=False)

    assert resolve_portable_project_identity(trusted) is not None
    assert resolve_portable_project_identity(unrelated) is None


def test_forged_clone_metadata_cannot_grant_portable_permission(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted" / "repo"
    forged = tmp_path / "forged" / "repo"
    remote = "https://github.com/example/trusted-repository.git"
    _init_repository(trusted, remote)
    _init_repository(forged, remote)

    trusted_identity = resolve_portable_project_identity(trusted)
    forged_identity = resolve_portable_project_identity(forged)
    assert trusted_identity is not None
    assert forged_identity == trusted_identity

    store = GuardStore(tmp_path / "guard-forged")
    bundle = _signed_project_memory_bundle(
        ("portable-allow", "allow", trusted_identity),
    )
    _activate_project_memory_bundle(store, bundle)

    assert (
        store.resolve_policy(
            "codex",
            "tool:read",
            workspace=str(forged),
            now=_NOW,
            consume_one_shot=False,
        )
        is None
    )


def test_gitdir_pointer_cannot_claim_external_repository_identity(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted" / "repo"
    pointer = tmp_path / "pointer"
    _init_repository(trusted, "https://github.com/example/trusted-repository.git")
    pointer.mkdir()
    (pointer / ".git").write_text(f"gitdir: {trusted / '.git'}\n", encoding="utf-8")

    assert resolve_portable_project_identity(pointer) is None


def test_portable_identity_accepts_legal_valueless_git_config_keys(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    _init_repository(repository, "https://example.invalid/owner/repository.git")
    config_path = repository / ".git" / "config"
    with config_path.open("a", encoding="utf-8") as handle:
        handle.write("\n[guard-test]\n\tbare\n")

    assert resolve_portable_project_identity(repository) is not None


def test_portable_project_identity_preserves_monorepo_subproject_scope(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    _init_repository(repository, "https://example.invalid/owner/repository.git")
    first_project = repository / "apps" / "first"
    second_project = repository / "apps" / "second"
    first_project.mkdir(parents=True)
    second_project.mkdir(parents=True)

    assert resolve_portable_project_identity(first_project) != resolve_portable_project_identity(second_project)


def test_project_identity_metadata_upgrades_path_like_project_id(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    _init_repository(repository, "ssh://git@example.invalid/owner/repository.git")

    identity = resolve_project_identity_from_metadata(
        {
            "project_id": str(repository),
            "workspace_path": str(repository),
        }
    )
    enriched = enrich_project_identity_metadata({"workspace_path": str(repository)})

    assert identity is not None
    assert is_portable_project_identity(identity)
    assert enriched["project_id"] == identity


def test_explicit_non_path_project_identity_remains_authoritative() -> None:
    metadata = {"project_id": "project:customer-api", "workspace_path": "/does/not/matter"}

    assert resolve_project_identity_from_metadata(metadata) == "project:customer-api"


def test_non_git_workspace_has_no_portable_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "plain"
    workspace.mkdir()

    assert resolve_portable_project_identity(workspace) is None


def test_restrictive_project_memory_created_on_one_clone_reuses_on_another_clone(tmp_path: Path) -> None:
    first = tmp_path / "laptop-a" / "repo"
    second = tmp_path / "laptop-b" / "repo"
    remote = "git@example.invalid:owner/repository.git"
    _init_repository(first, remote)
    _init_repository(second, remote)

    source_store = GuardStore(tmp_path / "guard-a")
    source_operation = _record_project_operation(source_store, first)
    metadata = source_operation.get("metadata")
    assert isinstance(metadata, dict)
    project_identity = metadata.get("project_id")
    assert is_portable_project_identity(project_identity)

    target_store = GuardStore(tmp_path / "guard-b")
    bundle = _signed_project_memory_bundle(
        ("remember-project", "block", str(project_identity)),
    )
    _activate_project_memory_bundle(target_store, bundle)

    assert (
        target_store.resolve_policy(
            "codex",
            "tool:read",
            workspace=str(second),
            now=_NOW,
            consume_one_shot=False,
        )
        == "block"
    )


def test_local_path_scope_remains_more_restrictive_than_portable_allow(tmp_path: Path) -> None:
    first = tmp_path / "laptop-a" / "repo"
    second = tmp_path / "laptop-b" / "repo"
    remote = "git@example.invalid:owner/repository.git"
    _init_repository(first, remote)
    _init_repository(second, remote)
    project_identity = resolve_portable_project_identity(first)
    assert project_identity is not None

    store = GuardStore(tmp_path / "guard-b")
    bundle = _signed_project_memory_bundle(
        ("portable-allow", "allow", project_identity),
        ("local-path-block", "block", str(second)),
    )
    _activate_project_memory_bundle(store, bundle)

    assert (
        store.resolve_policy(
            "codex",
            "tool:read",
            workspace=str(second),
            now=_NOW,
            consume_one_shot=False,
        )
        == "block"
    )


def test_portable_selector_does_not_turn_one_shot_approval_into_sticky_memory(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    _init_repository(workspace, "git@example.invalid:owner/repository.git")
    project_identity = resolve_portable_project_identity(workspace)
    assert project_identity is not None

    store = GuardStore(tmp_path / "guard-home")
    for request_id, decision_workspace in (
        ("request-once-local", str(workspace)),
        ("request-once-portable", project_identity),
    ):
        store.record_local_once_approval(
            request_id=request_id,
            harness="codex",
            artifact_id="tool:read-once",
            artifact_hash="sha256:once",
            workspace=decision_workspace,
            publisher=None,
            action="allow",
            created_at=_NOW,
            expires_at="2026-08-08T20:00:00+00:00",
        )

    first = store.resolve_policy(
        "codex",
        "tool:read-once",
        artifact_hash="sha256:once",
        workspace=str(workspace),
        now=_NOW,
    )
    second = store.resolve_policy(
        "codex",
        "tool:read-once",
        artifact_hash="sha256:once",
        workspace=str(workspace),
        now="2026-08-07T20:01:00+00:00",
    )

    assert first == "allow"
    assert second is None


def test_direct_portable_selector_does_not_apply_one_shot_permission(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    _init_repository(workspace, "git@example.invalid:owner/repository.git")
    project_identity = resolve_portable_project_identity(workspace)
    assert project_identity is not None

    store = GuardStore(tmp_path / "guard-home")
    for request_id in ("request-portable-1", "request-portable-2"):
        store.record_local_once_approval(
            request_id=request_id,
            harness="codex",
            artifact_id="tool:portable-once",
            artifact_hash="sha256:portable-once",
            workspace=project_identity,
            publisher=None,
            action="allow",
            created_at=_NOW,
            expires_at="2026-08-08T20:00:00+00:00",
        )

    first = store.resolve_policy(
        "codex",
        "tool:portable-once",
        artifact_hash="sha256:portable-once",
        workspace=project_identity,
        now=_NOW,
    )
    second = store.resolve_policy(
        "codex",
        "tool:portable-once",
        artifact_hash="sha256:portable-once",
        workspace=project_identity,
        now="2026-08-07T20:01:00+00:00",
    )
    third = store.resolve_policy(
        "codex",
        "tool:portable-once",
        artifact_hash="sha256:portable-once",
        workspace=project_identity,
        now="2026-08-07T20:02:00+00:00",
    )

    assert first is None
    assert second is None
    assert third is None
