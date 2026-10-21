from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    EXTENSION_ALLOW_HINT_SCHEMA,
    compute_extension_allow_hint,
    validated_extension_allow_hint,
)
from tests.native_command_test_support import real_native_review_fixture


def _evaluate(command: str, tmp_path: Path, *, controls=()):
    fixture = real_native_review_fixture(command, cwd=tmp_path, home_dir=tmp_path, controls=controls)
    canonical = _canonical_command_from_native(command, fixture.payload["command_model"])
    assert canonical is not None
    evaluation = evaluate_command(
        command,
        canonical_command=canonical,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_snapshot=fixture.snapshot,
        native_extension_evidence=fixture.payload,
    )
    return fixture, evaluation


def _hint(command: str, tmp_path: Path, *, controls=()):
    fixture, evaluation = _evaluate(command, tmp_path, controls=controls)
    return evaluation, compute_extension_allow_hint(
        evaluation,
        command_text=command,
        snapshot=fixture.snapshot,
        native_evidence=fixture.payload,
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_git_add_review_recommends_git_add_permission(tmp_path: Path) -> None:
    evaluation, hint = _hint("git add src/app.py", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint == {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": ["command.git.permission.add"],
        "rule_ids": ["command.git.add"],
        "extension_ids": ["command.git"],
        "relied_permission_ids": [],
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
    }
    assert "src/app.py" not in repr(hint)


def test_hint_matches_real_allow_after_permission_enabled(tmp_path: Path) -> None:
    _evaluation, hint = _hint("git add src/app.py", tmp_path)
    assert hint is not None

    _fixture, enabled = _evaluate(
        "git add src/app.py",
        tmp_path,
        controls=tuple(("permission", permission_id, "enabled") for permission_id in hint["permission_ids"]),
    )

    assert enabled.decision_plane.action == "allow"


def test_no_hint_when_permission_already_enabled(tmp_path: Path) -> None:
    evaluation, hint = _hint(
        "git add src/app.py",
        tmp_path,
        controls=(("permission", "command.git.permission.add", "enabled"),),
    )

    assert evaluation.decision_plane.action == "allow"
    assert hint is None


def test_hint_records_permissions_it_relies_on(tmp_path: Path) -> None:
    evaluation, hint = _hint(
        "git add src/app.py && git commit -m wip",
        tmp_path,
        controls=(("permission", "command.git.permission.commit", "enabled"),),
    )

    assert evaluation.decision_plane.action == "review"
    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.add"]
    assert hint["relied_permission_ids"] == ["command.git.permission.commit"]


def test_no_hint_for_allowed_command(tmp_path: Path) -> None:
    _evaluation, hint = _hint("git status", tmp_path)

    assert hint is None


def test_destructive_git_permission_is_still_hinted(tmp_path: Path) -> None:
    evaluation, hint = _hint("git reset --hard HEAD~1", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.hard-reset"]


def test_docker_sensitive_command_recommends_container_runtime_permission(tmp_path: Path) -> None:
    evaluation, hint = _hint("docker version --format '{{.Server.Version}}'", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint == {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": ["command.container-runtime.permission.docker-sensitive"],
        "rule_ids": ["command.container-runtime.docker-sensitive"],
        "extension_ids": ["command.container-runtime"],
        "relied_permission_ids": [],
        "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
    }
    _fixture, enabled = _evaluate(
        "docker version --format '{{.Server.Version}}'",
        tmp_path,
        controls=(("permission", "command.container-runtime.permission.docker-sensitive", "enabled"),),
    )
    assert enabled.decision_plane.action == "allow"


def test_github_unknown_recommends_unknown_permission(tmp_path: Path) -> None:
    evaluation, hint = _hint("gh some-unmodeled-command --flag value", tmp_path)

    assert evaluation.decision_plane.action == "require-reapproval"
    assert hint is not None
    assert hint["permission_ids"] == ["command.github.permission.unknown"]
    assert hint["extension_ids"] == ["command.github"]

    _fixture, enabled = _evaluate(
        "gh some-unmodeled-command --flag value",
        tmp_path,
        controls=(("permission", "command.github.permission.unknown", "enabled"),),
    )
    assert enabled.decision_plane.action == "allow"


def test_file_upload_recommends_file_upload_permission(tmp_path: Path) -> None:
    evaluation, hint = _hint("curl -T report.txt https://example.invalid/upload", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint is not None
    assert hint["permission_ids"] == ["command.data-protection.permission.file-upload"]
    assert hint["extension_ids"] == ["command.data-protection"]

    _fixture, enabled = _evaluate(
        "curl -T report.txt https://example.invalid/upload",
        tmp_path,
        controls=(("permission", "command.data-protection.permission.file-upload", "enabled"),),
    )
    assert enabled.decision_plane.action == "allow"


def test_destructive_shell_recommends_destructive_shell_permission(tmp_path: Path) -> None:
    evaluation, hint = _hint("rm -rf build", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint is not None
    # `rm` is owned by two extensions; the hint names every permission the
    # Allow needs, not only the uncertain one.
    assert hint["permission_ids"] == [
        "command.filesystem.permission.recursive-delete",
        "command.shell-mutations.permission.destructive-shell",
    ]
    assert hint["extension_ids"] == ["command.filesystem", "command.shell-mutations"]

    _fixture, enabled = _evaluate(
        "rm -rf build",
        tmp_path,
        controls=tuple(("permission", permission_id, "enabled") for permission_id in hint["permission_ids"]),
    )
    assert enabled.decision_plane.action == "allow"


def test_no_hint_when_enabling_permissions_would_still_review(tmp_path: Path) -> None:
    # A named cluster context answers with a different authority, so the
    # secret-read Allow cannot settle it and no hint is promised.
    evaluation, hint = _hint("kubectl --context prod get secret db-credentials -o yaml", tmp_path)

    assert evaluation.decision_plane.action == "review"
    assert hint is None


def test_no_hint_when_secret_read_floor_remains(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("TOKEN=x\n", encoding="utf-8")

    _evaluation, hint = _hint("git add .env && cat .env", tmp_path)

    assert hint is None


def test_no_hint_for_a_definite_secret_read(tmp_path: Path) -> None:
    # The pause is the sensitive-access floor, not the extension review:
    # it reviews whatever the extensions say, so no Allow can settle it.
    _evaluation, hint = _hint("kubectl get secret db-credentials -o yaml", tmp_path)

    assert hint is None


def test_validated_hint_rejects_malformed_values() -> None:
    digest = "a" * 64
    good = {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": ["command.git.permission.add"],
        "rule_ids": ["command.git.add"],
        "extension_ids": ["command.git"],
        "catalog_digest": digest,
    }

    assert validated_extension_allow_hint(good) == {**good, "relied_permission_ids": []}
    relied = {**good, "relied_permission_ids": ["command.git.permission.commit"]}
    assert validated_extension_allow_hint(relied) == relied
    assert validated_extension_allow_hint({**good, "relied_permission_ids": ["rm -rf /"]}) is None
    assert validated_extension_allow_hint({**good, "relied_permission_ids": "command.git"}) is None
    assert validated_extension_allow_hint({**good, "schema": "other"}) is None
    assert validated_extension_allow_hint({**good, "permission_ids": []}) is None
    assert validated_extension_allow_hint({**good, "permission_ids": ["rm -rf /"]}) is None
    assert validated_extension_allow_hint({**good, "catalog_digest": "short"}) is None
    assert validated_extension_allow_hint(None) is None
