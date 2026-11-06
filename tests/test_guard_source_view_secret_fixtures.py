from __future__ import annotations

from pathlib import Path

import pytest

from tests.live_hook_review_support import LIVE_REVIEWS_RETIRED_ALLOW, live_post_tool_flag


def _write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    (
        ("Read", {"file_path": "src/config.py"}),
        ("mcp__hub__describe", {"skill": "guard-dev-testing"}),
    ),
)
def test_codex_non_shell_post_tool_secret_output_is_blocked(
    live_hook_root: Path,
    tool_name: str,
    tool_input: dict[str, str],
) -> None:
    token = "".join(("gh", "p_")) + "a" * 30
    artifact = live_post_tool_flag(
        payload={
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_response": {"stdout": f"token={token}"},
        },
        cwd=live_hook_root,
        home_dir=live_hook_root,
    )

    assert artifact is not None


@LIVE_REVIEWS_RETIRED_ALLOW
def test_codex_source_view_allows_placeholder_private_key_fixture_output(live_hook_root: Path) -> None:
    workspace_dir = live_hook_root / "workspace"
    source_file = workspace_dir / "tests" / "test_connect_fixture.py"
    _write_text(
        source_file,
        ('dpop_private_key_pem="-----BEGIN ' + 'PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----\n"\n'),
    )

    command = "sed -n '1,20p' tests/test_connect_fixture.py"

    artifact = live_post_tool_flag(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_file.read_text(encoding="utf-8")},
        },
        cwd=workspace_dir,
    )

    assert artifact is None


def test_codex_source_view_allows_oauth_token_service_source_output(live_hook_root: Path) -> None:
    workspace_dir = live_hook_root / "workspace"
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

    artifact = live_post_tool_flag(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_contents},
        },
        cwd=workspace_dir,
    )

    assert artifact is None


def test_codex_source_view_allows_medium_examples_from_symlinked_skill(live_hook_root: Path) -> None:
    home_dir = live_hook_root / "home"
    workspace_dir = live_hook_root / "workspace"
    real_skill = workspace_dir / ".agents" / "skills" / "guard-dev-testing"
    skill_file = real_skill / "SKILL.md"
    _write_text(skill_file, "secret = get_secret('deployment-config')\nsecret['data'] = merged\n")
    linked_skill = home_dir / ".agents" / "skills" / "guard-dev-testing"
    linked_skill.parent.mkdir(parents=True)
    linked_skill.symlink_to(real_skill, target_is_directory=True)
    command = f"sed -n '1,20p' {linked_skill / 'SKILL.md'}"

    artifact = live_post_tool_flag(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": skill_file.read_text(encoding="utf-8")},
        },
        cwd=workspace_dir,
        home_dir=home_dir,
    )

    assert artifact is None


def test_codex_source_view_still_blocks_real_private_key_output(live_hook_root: Path) -> None:
    workspace_dir = live_hook_root / "workspace"
    source_file = workspace_dir / "tests" / "test_connect_fixture.py"
    _write_text(
        source_file,
        (
            'dpop_private_key_pem="-----BEGIN '
            + "PRIVATE KEY-----\n"
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD0realmaterial\n"
            + '-----END PRIVATE KEY-----\n"\n'
        ),
    )

    command = "sed -n '1,20p' tests/test_connect_fixture.py"

    artifact = live_post_tool_flag(
        payload={
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": source_file.read_text(encoding="utf-8")},
        },
        cwd=workspace_dir,
    )

    assert artifact is not None
