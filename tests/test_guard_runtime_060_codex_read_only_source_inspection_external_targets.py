"""Runtime regression tests: codex read only source inspection external targets."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    Path,
    guard_commands_module,
    pytest,
    shlex,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _isolate_git_config,
    _write_text,
)


def test_codex_read_only_source_inspection_external_targets_require_plain_non_recursive_grep(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    projects_dir = home_dir / "projects"
    workspace_dir = projects_dir / "workspace"
    source_root = projects_dir / "sibling-worktree"
    source_file = source_root / "src" / "safe.ts"
    workspace_dir.mkdir(parents=True)
    source_file.parent.mkdir(parents=True)
    source_file.write_text("export const browser = true;\n")
    (source_root / ".git").write_text("gitdir: ../.git/worktrees/test-checkout\n")

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        f"grep 'browser' {source_file}",
        cwd=workspace_dir,
        home_dir=home_dir,
    )

    workspace_source = workspace_dir / "src" / "local.ts"
    workspace_source.parent.mkdir()
    workspace_source.write_text("export const browser = true;\n")
    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        f"grep -r 'browser' {workspace_source.parent}",
        cwd=workspace_dir,
        home_dir=home_dir,
    )

    rejected_commands = (
        f"grep -r 'browser' {source_file.parent}",
        f"grep -R 'browser' {source_file.parent}",
        f"grep -rn 'browser' {source_file.parent}",
        f"grep -nR 'browser' {source_file.parent}",
        f"grep --recursive 'browser' {source_file.parent}",
        f"grep --dereference-recursive 'browser' {source_file.parent}",
        f"grep -d recurse 'browser' {source_file.parent}",
        f"grep -drecurse 'browser' {source_file.parent}",
        f"grep --directories=recurse 'browser' {source_file.parent}",
        f"grep --directories recurse 'browser' {source_file.parent}",
        f"rg 'browser' {source_file}",
        f"git grep 'browser' {source_file}",
        f"bash -c \"grep 'browser' {source_file}\"",
    )
    for command in rejected_commands:
        assert not guard_commands_module._codex_command_is_read_only_source_inspection(
            command,
            cwd=workspace_dir,
            home_dir=home_dir,
        )


def test_codex_read_only_source_inspection_rejects_globbed_targets(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    (workspace_dir / "src").mkdir(parents=True)
    _write_text(workspace_dir / "src" / "safe.ts", "export const safe = true;\n")

    commands = [
        "cat src/*.ts",
        "cat src/[leak].ts",
        "sed -n '1,40p' src/*.ts | head -40",
        "rg safe src/*.ts",
    ]

    for command in commands:
        assert not guard_commands_module._codex_command_is_read_only_source_inspection(
            command,
            cwd=workspace_dir,
        )


def test_codex_read_only_source_inspection_allows_quoted_bracket_targets(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    route_file = workspace_dir / "app" / "[slug]" / "page.tsx"
    _write_text(route_file, "export default function Page() { return null; }\n")

    commands = [
        "cat 'app/[slug]/page.tsx'",
        "sed -n '1,40p' 'app/[slug]/page.tsx' | head -40",
        "rg Page 'app/[slug]/page.tsx'",
    ]

    for command in commands:
        assert guard_commands_module._codex_command_is_read_only_source_inspection(
            command,
            cwd=workspace_dir,
        )


def test_codex_read_only_source_inspection_allows_safe_sed_chains(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    route_file = workspace_dir / "src" / "api" / "routes" / "skill-registry.ts"
    service_file = workspace_dir / "src" / "services" / "skill-registry" / "skill-registry-service.ts"
    _write_text(route_file, "export const headerName = 'x-api-key';\n")
    _write_text(service_file, "export const registryTokenField = 'tokenId';\n")

    command = (
        "sed -n '450,510p' src/api/routes/skill-registry.ts && "
        "sed -n '940,1005p' src/services/skill-registry/skill-registry-service.ts"
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace_dir,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": "export const headerName = 'x-api-key';\nexport const registryTokenField = 'tokenId';\n"
            },
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )
    assert artifact is None


def test_codex_read_only_source_inspection_rejects_unbounded_sed_ranges(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "sed -n '9999999p' src/safe.ts",
        cwd=workspace_dir,
    )
    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        f"sed -n '{'9' * 10000}p' src/safe.ts",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_sed_chain_with_secret_file(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    route_file = workspace_dir / "src" / "api" / "routes" / "skill-registry.ts"
    _write_text(route_file, "export const safe = true;\n")

    command = "sed -n '450,510p' src/api/routes/skill-registry.ts && cat .env"

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_preserves_pipelines_in_safe_chains(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    route_file = workspace_dir / "src" / "api" / "routes" / "skill-registry.ts"
    service_file = workspace_dir / "src" / "services" / "skill-registry" / "skill-registry-service.ts"
    _write_text(route_file, "export const safe = true;\n")
    _write_text(service_file, "export const alsoSafe = true;\n")

    command = (
        "rg skill src/api/routes/skill-registry.ts | head -20 && "
        "sed -n '940,1005p' src/services/skill-registry/skill-registry-service.ts"
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_allows_cd_then_bounded_secret_term_search(tmp_path: Path) -> None:
    repo_root = tmp_path / "CascadeProjects" / "hashgraph-online"
    workspace_dir = repo_root / "hol-points-portal" / ".worktrees" / "guard-auth-phase-r-removal"
    source_file = workspace_dir / "src" / "guard-auth.ts"
    live_prefix = "guard" + "_live" + "_"
    _write_text(
        source_file,
        "export const legacy_runtime_material_rejected = 'agent_token field name only';\n",
    )
    pattern = (
        f"{live_prefix}|service_principal|agent_token|migration_failure|"
        "legacy_runtime_material_rejected|legacy_issuance_attempt_rejected|legacy.*report|reauthorization"
    )

    command = (
        f"cd {shlex.quote(str(workspace_dir))} && "
        f"rg -n {shlex.quote(pattern)} src app __tests__ docs -g '!**/*.map' | sed -n '1,260p'"
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=repo_root,
        home_dir=tmp_path,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": (
                    "src/guard-auth.ts:1:"
                    "export const legacy_runtime_material_rejected = 'agent_token field name only';\n"
                )
            },
        },
        config_path=str(repo_root / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=repo_root,
        home_dir=tmp_path,
    )
    assert artifact is None


def test_codex_read_only_source_inspection_rejects_cd_parent_escape(tmp_path: Path) -> None:
    repo_root = tmp_path / "CascadeProjects" / "hashgraph-online"
    workspace_dir = repo_root / "hol-points-portal" / ".worktrees" / "guard-auth-phase-r-removal"
    outside_dir = tmp_path / "CascadeProjects" / "outside"
    _write_text(workspace_dir / "src" / "inside.ts", "export const token_label = 'field name only';\n")
    _write_text(outside_dir / "src" / "outside.ts", "export const token_label = 'field name only';\n")

    command = (
        f"cd {shlex.quote(str(workspace_dir / '..' / '..' / '..' / '..' / 'outside'))} && "
        "rg -n token_label src | sed -n '1,40p'"
    )

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=repo_root,
        home_dir=tmp_path,
    )


def test_codex_read_only_source_inspection_allows_tilde_worktree_targets(tmp_path: Path) -> None:
    repo_root = tmp_path / "CascadeProjects" / "hashgraph-online"
    workspace_dir = repo_root / "hol-points-portal" / ".worktrees" / "guard-auth-phase-r-default-surfaces"
    _write_text(
        workspace_dir / "app" / "agent-token-detail.tsx",
        "export type AgentTokenDetail = { tokenId: string };\n",
    )
    _write_text(workspace_dir / "__tests__" / "agent-token-detail.test.ts", "expect(onRotated).toHaveBeenCalled();\n")

    command = (
        'rg -n "onRotated=|onRotated:|onRotated\\)|AgentTokenDetail" '
        "~/CascadeProjects/hashgraph-online/hol-points-portal/.worktrees/guard-auth-phase-r-default-surfaces/app "
        "~/CascadeProjects/hashgraph-online/hol-points-portal/.worktrees/guard-auth-phase-r-default-surfaces/__tests__"
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=repo_root,
        home_dir=tmp_path,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": (
                    "app/agent-token-detail.tsx:1:export type AgentTokenDetail = { tokenId: string };\n"
                    "__tests__/agent-token-detail.test.ts:1:expect(onRotated).toHaveBeenCalled();\n"
                )
            },
        },
        config_path=str(repo_root / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=repo_root,
        home_dir=tmp_path,
    )
    assert artifact is None


@pytest.mark.parametrize(
    "command",
    (
        "rg -n \"token\" src | sed -n '1,40p'",
        "nl -ba src/config.ts | sed -n '1,40p'",
        "wc -l src/config.ts; sed -n '1,40p' src/config.ts",
        "yq '.jobs' .github/workflows/publish.yml",
    ),
)
def test_codex_read_only_source_inspection_still_blocks_value_like_secret_output(
    command: str,
    tmp_path: Path,
) -> None:
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / "src" / "config.ts", "export const label = 'token';\n")
    _write_text(workspace_dir / ".github" / "workflows" / "publish.yml", "jobs: {}\n")

    synthetic_github_pat = "ghp_" + ("1234567890" * 4)[:36]
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": f"src/config.ts:1:export const token = '{synthetic_github_pat}';\n"},
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )
    assert artifact is not None


def test_codex_read_only_source_inspection_allows_git_diff_with_bounded_sed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_paths = [
        workspace_dir / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "server.py",
        workspace_dir / "dashboard" / "src" / "approval-center-layout.tsx",
        workspace_dir / "dashboard" / "src" / "review-workspace.tsx",
        workspace_dir / "tests" / "test_guard_approvals.py",
    ]
    for path in source_paths:
        _write_text(path, "TOKEN_LABEL = 'credential-looking output text only'\n")

    command = (
        "git diff -- "
        "src/codex_plugin_scanner/guard/daemon/server.py "
        "dashboard/src/approval-center-layout.tsx "
        "dashboard/src/review-workspace.tsx "
        "tests/test_guard_approvals.py | sed -n '1,260p'"
    )

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace_dir,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": (
                    "+TOKEN_LABEL = 'credential-looking output text only'\n"
                    "+request_summary = 'credential-looking output reached Codex'\n"
                )
            },
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )
    assert artifact is None


def test_codex_read_only_source_inspection_rejects_git_diff_secret_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    _write_text(workspace_dir / ".env", "TOKEN_LABEL=value\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- .env | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_external_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[diff]
    external = /tmp/guard-helper
""".strip(),
    )

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_textconv_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[diff "guard"]
    textconv = /tmp/guard-textconv
""".strip(),
    )

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_diff_driver_command_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")
    _write_text(
        workspace_dir / ".git" / "config",
        """
[diff "guard"]
    command = /tmp/guard-diff
""".strip(),
    )

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_external_diff_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/tmp/guard-helper")
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )


def test_codex_read_only_source_inspection_rejects_git_config_parameters_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_git_config(monkeypatch)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'diff.external=/tmp/guard-helper'")
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "safe.ts"
    _write_text(source_file, "export const safe = true;\n")

    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        "git diff -- src/safe.ts | sed -n '1,40p'",
        cwd=workspace_dir,
    )
