"""Tests for the shared source-path classification module."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.source_paths import (
    SOURCE_CLASSIFIER_VERSION,
    SourcePathDecision,
    path_contains_symlink,
    resolve_source_candidate_path,
    source_path_is_allowed,
)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "home" / "workspace"
    ws.mkdir(parents=True)
    (ws / "src").mkdir()
    (ws / "docs").mkdir()
    (ws / "lib").mkdir()
    return ws


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    hd = tmp_path / "home"
    hd.mkdir(exist_ok=True)
    return hd


def _write_worktree_git_marker(checkout_root: Path) -> None:
    checkout_root.mkdir(parents=True, exist_ok=True)
    (checkout_root / ".git").write_text("gitdir: ../.git/worktrees/test-checkout\n")


class TestSourceClassifierVersion:
    def test_version_is_stable_string(self) -> None:
        assert SOURCE_CLASSIFIER_VERSION == "source-paths-v1"


class TestSourcePathIsAllowed:
    def test_ts_file_under_src_allowed(self, workspace: Path, home_dir: Path) -> None:
        (workspace / "src" / "foo.ts").write_text("export const x = 1;")
        decision = source_path_is_allowed("src/foo.ts", cwd=workspace, home_dir=home_dir)
        assert decision.allowed
        assert decision.reason_code == "source_prefix"

    def test_tsx_file_under_src_allowed(self, workspace: Path, home_dir: Path) -> None:
        (workspace / "src" / "component.tsx").write_text("<div/>")
        decision = source_path_is_allowed("src/component.tsx", cwd=workspace, home_dir=home_dir)
        assert decision.allowed

    def test_py_file_allowed(self, workspace: Path, home_dir: Path) -> None:
        (workspace / "src" / "app.py").write_text("x = 1")
        decision = source_path_is_allowed("src/app.py", cwd=workspace, home_dir=home_dir)
        assert decision.allowed

    def test_md_file_under_docs_allowed(self, workspace: Path, home_dir: Path) -> None:
        (workspace / "docs" / "spec.md").write_text("# Spec")
        decision = source_path_is_allowed("docs/spec.md", cwd=workspace, home_dir=home_dir)
        assert decision.allowed

    def test_env_rejected(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".env").write_text("SECRET=abc")
        decision = source_path_is_allowed(".env", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed
        assert decision.reason_code == "sensitive_basename"

    def test_npmrc_rejected(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".npmrc").write_text("authToken=abc")
        decision = source_path_is_allowed(".npmrc", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed

    def test_netrc_rejected(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".netrc").write_text("machine example.com")
        decision = source_path_is_allowed(".netrc", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed

    def test_git_credentials_rejected(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".git-credentials").write_text("https://user:pass@example.com")
        decision = source_path_is_allowed(".git-credentials", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed

    def test_hidden_unsafe_dir_rejected(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".secret").mkdir()
        (workspace / ".secret" / "data.ts").write_text("x")
        decision = source_path_is_allowed(".secret/data.ts", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed
        assert decision.reason_code == "unsafe_hidden_dir"

    def test_workflow_source_file_allowed(self, workspace: Path, home_dir: Path) -> None:
        workflow = workspace / ".github" / "workflows" / "publish.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("jobs: {}\n")

        decision = source_path_is_allowed(
            ".github/workflows/publish.yml",
            cwd=workspace,
            home_dir=home_dir,
        )

        assert decision.allowed
        assert decision.reason_code == "source_extension"

    def test_other_hidden_github_source_file_rejected(self, workspace: Path, home_dir: Path) -> None:
        hidden_source = workspace / ".github" / "private" / "config.yml"
        hidden_source.parent.mkdir(parents=True)
        hidden_source.write_text("token: fixture\n")

        decision = source_path_is_allowed(
            ".github/private/config.yml",
            cwd=workspace,
            home_dir=home_dir,
        )

        assert not decision.allowed
        assert decision.reason_code == "unsafe_hidden_dir"

    def test_workflow_source_symlink_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.yml"
        outside.write_text("token: fixture\n")
        workflow = workspace / ".github" / "workflows" / "publish.yml"
        workflow.parent.mkdir(parents=True)
        workflow.symlink_to(outside)

        decision = source_path_is_allowed(
            ".github/workflows/publish.yml",
            cwd=workspace,
            home_dir=home_dir,
        )

        assert not decision.allowed
        assert decision.reason_code == "symlink_in_path"

    def test_benign_dotfile_allowed(self, workspace: Path, home_dir: Path) -> None:
        (workspace / ".nvmrc").write_text("20")
        decision = source_path_is_allowed(".nvmrc", cwd=workspace, home_dir=home_dir)
        assert decision.allowed

    def test_empty_target_rejected(self, workspace: Path, home_dir: Path) -> None:
        decision = source_path_is_allowed("", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed
        assert decision.reason_code == "empty_path"

    def test_glob_pattern_rejected(self, workspace: Path, home_dir: Path) -> None:
        decision = source_path_is_allowed("src/*.ts", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed
        assert decision.reason_code == "glob_pattern"

    def test_absolute_path_outside_workspace_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.ts"
        outside.write_text("x")
        decision = source_path_is_allowed(str(outside), cwd=workspace, home_dir=home_dir)
        assert not decision.allowed

    def test_external_source_path_requires_explicit_search_opt_in(
        self, workspace: Path, home_dir: Path, tmp_path: Path
    ) -> None:
        source_file = (home_dir / "sibling-source" / "scripts" / "guard-test").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("#!/bin/sh\n")
        _write_worktree_git_marker(home_dir / "sibling-source")

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert decision.allowed
        assert decision.reason_code == "external_source_path"

    def test_external_source_path_under_sibling_git_directory_allowed(self, workspace: Path, home_dir: Path) -> None:
        source_root = home_dir / "sibling-repository"
        source_file = (source_root / "src" / "main.py").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("value = 1\n")
        (source_root / ".git").mkdir()

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert decision.allowed
        assert decision.reason_code == "external_source_path"

    def test_external_source_path_in_downloads_nested_git_checkout_rejected(
        self, workspace: Path, home_dir: Path
    ) -> None:
        nested_checkout = home_dir / "Downloads" / "app"
        source_file = (nested_checkout / "src" / "main.py").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("value = 1\n")
        (nested_checkout / ".git").mkdir()

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "external_target_not_sibling_git_checkout"

    def test_external_source_path_outside_home_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        source_file = (tmp_path / "outside-home" / "scripts" / "guard-test").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("#!/bin/sh\n")

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "external_target_outside_home"

    def test_external_source_path_without_home_rejected(self, workspace: Path, home_dir: Path) -> None:
        source_file = (home_dir / "sibling-source" / "scripts" / "guard-test").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("#!/bin/sh\n")
        _write_worktree_git_marker(home_dir / "sibling-source")

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=None,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "external_home_unavailable"

    def test_external_source_path_with_unresolvable_home_rejected(
        self, workspace: Path, home_dir: Path, tmp_path: Path
    ) -> None:
        source_file = (home_dir / "sibling-source" / "scripts" / "guard-test").resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("#!/bin/sh\n")
        _write_worktree_git_marker(home_dir / "sibling-source")

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=tmp_path / "missing-home",
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "external_home_unavailable"

    def test_external_search_opt_in_rejects_relative_escape(
        self, workspace: Path, home_dir: Path, tmp_path: Path
    ) -> None:
        source_file = home_dir / "external-source" / "scripts" / "guard-test"
        source_file.parent.mkdir(parents=True)
        source_file.write_text("#!/bin/sh\n")

        decision = source_path_is_allowed(
            "../external-source/scripts/guard-test",
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "absolute_path_outside_workspace"

    def test_external_sensitive_path_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        secret_file = (home_dir / "sibling-source" / "credentials" / "config.ts").resolve()
        secret_file.parent.mkdir(parents=True)
        secret_file.write_text("credential = 'value'\n")
        _write_worktree_git_marker(home_dir / "sibling-source")

        decision = source_path_is_allowed(
            str(secret_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "sensitive_basename"

    @pytest.mark.parametrize("filename", ("secrets.json", "credentials.yaml", "auth_token.ts"))
    def test_external_sensitive_filename_rejected(
        self,
        workspace: Path,
        home_dir: Path,
        filename: str,
    ) -> None:
        source_root = home_dir / "sibling-source"
        source_file = (source_root / filename).resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("value = 1\n")
        _write_worktree_git_marker(source_root)

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "sensitive_basename"

    @pytest.mark.parametrize("filename", ("authentication.ts", "tokenizer.ts", "secretary.ts"))
    def test_external_sensitive_filename_avoids_substring_false_positives(
        self,
        workspace: Path,
        home_dir: Path,
        filename: str,
    ) -> None:
        source_root = home_dir / "sibling-source"
        source_file = (source_root / filename).resolve()
        source_file.parent.mkdir(parents=True)
        source_file.write_text("value = 1\n")
        _write_worktree_git_marker(source_root)

        decision = source_path_is_allowed(
            str(source_file),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert decision.allowed
        assert decision.reason_code == "external_source_path"

    def test_external_symlinked_source_path_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        source_root = (home_dir / "sibling-source").resolve()
        real_file = source_root / "scripts" / "guard-test"
        real_file.parent.mkdir(parents=True)
        real_file.write_text("#!/bin/sh\n")
        _write_worktree_git_marker(source_root)
        link = source_root / "scripts" / "linked-guard-test"
        try:
            link.symlink_to(real_file)
        except OSError as exc:
            pytest.skip(f"Cannot create symlinks: {exc}")

        decision = source_path_is_allowed(
            str(link),
            cwd=workspace,
            home_dir=home_dir,
            allow_external_source=True,
        )

        assert not decision.allowed
        assert decision.reason_code == "symlink_in_path"

    def test_relative_path_escape_rejected(self, workspace: Path, home_dir: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.ts"
        outside.write_text("x")
        decision = source_path_is_allowed("../../outside.ts", cwd=workspace, home_dir=home_dir)
        assert not decision.allowed

    def test_json_file_allowed_by_extension(self, workspace: Path, home_dir: Path) -> None:
        (workspace / "package.json").write_text("{}")
        decision = source_path_is_allowed("package.json", cwd=workspace, home_dir=home_dir)
        assert decision.allowed
        assert decision.reason_code == "source_extension"

    def test_absolute_symlink_inside_workspace_rejected(self, workspace: Path, tmp_path: Path) -> None:
        """Regression: an absolute path that contains a symlink must be rejected.

        Previously the absolute-path branch called .resolve() before
        path_contains_symlink(), which followed the symlink and hid it.
        """
        outside = tmp_path / "evil.txt"
        outside.write_text("secret")
        link = workspace / "src" / "link.ts"
        try:
            os.symlink(outside, link)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")
        # Pass the absolute path of the symlink
        decision = source_path_is_allowed(str(link), cwd=workspace, home_dir=None)
        assert not decision.allowed
        assert decision.reason_code == "symlink_in_path"

    def test_relative_symlink_inside_workspace_rejected(self, workspace: Path, tmp_path: Path) -> None:
        """Relative-path symlinks must also be rejected (existing behavior)."""
        outside = tmp_path / "evil.txt"
        outside.write_text("secret")
        link = workspace / "src" / "link.ts"
        try:
            os.symlink(outside, link)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")
        decision = source_path_is_allowed("src/link.ts", cwd=workspace, home_dir=None)
        assert not decision.allowed
        assert decision.reason_code == "symlink_in_path"


class TestPathContainsSymlink:
    def test_symlink_pointing_outside_rejected(self, workspace: Path, tmp_path: Path) -> None:
        target = tmp_path / "evil.txt"
        target.write_text("secret")
        link = workspace / "link.ts"
        try:
            os.symlink(target, link)
        except OSError:
            pytest.skip("Cannot create symlinks on this platform")
        assert path_contains_symlink(link, base_dir=workspace) is True

    def test_normal_file_no_symlink(self, workspace: Path) -> None:
        (workspace / "src" / "foo.ts").write_text("x")
        assert path_contains_symlink(workspace / "src" / "foo.ts", base_dir=workspace) is False

    def test_path_outside_base_returns_true(self, workspace: Path, tmp_path: Path) -> None:
        outside = tmp_path / "outside.ts"
        outside.write_text("x")
        assert path_contains_symlink(outside, base_dir=workspace) is True


class TestResolveSourceCandidatePath:
    def test_relative_path_resolves_under_cwd(self, workspace: Path) -> None:
        result = resolve_source_candidate_path("src/foo.ts", cwd=workspace, home_dir=None)
        assert result is not None
        assert result == (workspace / "src" / "foo.ts").resolve()

    def test_absolute_path_returns_as_is(self, tmp_path: Path) -> None:
        abs_path = str(tmp_path / "foo.ts")
        result = resolve_source_candidate_path(abs_path, cwd=None, home_dir=None)
        assert result is not None
        assert str(result) == abs_path

    def test_tilde_path_with_home_dir(self, home_dir: Path) -> None:
        result = resolve_source_candidate_path("~/foo.ts", cwd=None, home_dir=home_dir)
        assert result is not None
        assert result == (home_dir / "foo.ts").resolve()

    def test_tilde_path_without_home_dir_returns_none(self) -> None:
        result = resolve_source_candidate_path("~/foo.ts", cwd=None, home_dir=None)
        assert result is None

    def test_empty_target_returns_none(self) -> None:
        assert resolve_source_candidate_path("", cwd=None, home_dir=None) is None


class TestSourcePathDecision:
    def test_frozen_dataclass(self) -> None:
        decision = SourcePathDecision(allowed=True, reason_code="test")
        try:
            decision.allowed = False  # type: ignore[misc]
        except AttributeError:
            pass
        else:
            raise AssertionError("SourcePathDecision should be frozen")
