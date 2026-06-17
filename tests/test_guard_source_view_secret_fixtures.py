from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.cli import commands as guard_commands_module


def _write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def test_codex_source_view_allows_placeholder_private_key_fixture_output(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "tests" / "test_connect_fixture.py"
    _write_text(
        source_file,
        ('dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n"\n'),
    )

    command = "sed -n '1,20p' tests/test_connect_fixture.py"

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        command,
        cwd=workspace_dir,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_file.read_text(encoding="utf-8")},
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )

    assert artifact is None


def test_codex_source_view_allows_oauth_token_service_source_output(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "src" / "oauth-token-service.ts"
    source_contents = (
        "export class OAuthTokenService {\n"
        "  refreshAccessToken(): string {\n"
        '    return "placeholder-access-token";\n'
        "  }\n"
        "}\n"
    )
    _write_text(source_file, source_contents)

    command = "sed -n '1,20p' src/oauth-token-service.ts"

    assert not guard_commands_module._codex_command_targets_secret_like_source_name(
        command,
        cwd=workspace_dir,
    )
    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_contents},
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )

    assert artifact is None


def test_codex_source_view_compound_token_stem_stays_non_secret_without_cwd() -> None:
    command = "sed -n '1,20p' src/oauth-token-service.ts"

    assert not guard_commands_module._codex_command_targets_secret_like_source_name(command)
    assert guard_commands_module._codex_command_targets_secret_like_source_name("sed -n '1,20p' token.ts")


def test_codex_source_view_exact_secret_stem_stays_secret_with_cwd(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "config" / "secrets.yaml"
    _write_text(source_file, "token: fixture-only\n")

    assert guard_commands_module._codex_command_targets_secret_like_source_name(
        "head -40 config/secrets.yaml",
        cwd=workspace_dir,
    )


def test_codex_source_view_still_blocks_real_private_key_output(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    source_file = workspace_dir / "tests" / "test_connect_fixture.py"
    _write_text(
        source_file,
        (
            'dpop_private_key_pem="-----BEGIN PRIVATE KEY-----\n'
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD0realmaterial\n"
            '-----END PRIVATE KEY-----\n"\n'
        ),
    )

    command = "sed -n '1,20p' tests/test_connect_fixture.py"

    artifact = guard_commands_module._codex_post_tool_output_artifact(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_file.read_text(encoding="utf-8")},
        },
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=workspace_dir,
    )

    assert artifact is not None
