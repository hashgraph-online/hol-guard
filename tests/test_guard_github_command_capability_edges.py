from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.github_capability_contract import GitHubCommandCapability
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("args", "expected_capabilities"),
    (
        (("pr", "merge", "123", "--squash"), ("merge_remote",)),
        (("pr", "merge", "123", "--admin"), ("admin_merge_remote",)),
        (
            ("pr", "merge", "123", "--admin", "--delete-branch"),
            ("admin_merge_remote", "delete_remote"),
        ),
        (("pr", "merge", "123", "--admin=true"), ("admin_merge_remote",)),
        (("pr", "merge", "123", "--admin=1"), ("admin_merge_remote",)),
        (("pr", "merge", "123", "--admin=false"), ("merge_remote",)),
        (("pr", "merge", "123", "--admin=0"), ("merge_remote",)),
        (("pr", "merge", "123", "--admin=maybe"), ("unknown",)),
        (("pr", "merge", "123", "--adminx"), ("merge_remote",)),
        (("pr", "merge", "123", "--", "--admin"), ("merge_remote",)),
    ),
)
def test_pr_merge_admin_capability_matches_github_boolean_option_semantics(
    args: tuple[str, ...],
    expected_capabilities: tuple[GitHubCommandCapability, ...],
) -> None:
    assert classify_github_cli(args).capabilities == expected_capabilities


@pytest.mark.parametrize(
    "command",
    (
        "$PYTHON --version",
        "${PAGER:-less} README.md",
        "env TOOL=ruff sh -c '$TOOL check .'",
        "$TOOL --version; TOOL=gh",
        "TOOL=gh; TOOL=echo; $TOOL hello",
        "tool=gh; $TOOL hello",
        "TOOL=gh env; $TOOL hello",
        "TOOL=gh; sh -c 'TOOL=echo; $TOOL hello'",
        "TOOL=gh; export TOOL=python; $TOOL --version",
        "TOOL=gh; readonly TOOL=python; $TOOL --version",
        "TOOL=gh; declare TOOL=python; $TOOL --version",
        "TOOL=gh; typeset TOOL=python; $TOOL --version",
        "TOOL=gh; unset TOOL; $TOOL --version",
        "export TOOL=$(command -v gh); export TOOL=python; $TOOL --version",
        "TOOL=gh; sh -c '$TOOL repo delete o/r --yes'",
        "TOOL=python; false && TOOL=gh; $TOOL --version",
        "TOOL=python; true || TOOL=gh; $TOOL --version",
        "CMD='echo ok'; false && CMD='gh repo delete o/r --yes'; eval \"$CMD\"",
        "CMD='echo ok'; true || CMD='gh repo delete o/r --yes'; eval \"$CMD\"",
        "$TOOL --version; TOOL=$(command -v gh)",
        "TOOL=$(command -v gh); TOOL=echo; $TOOL hello",
        "tool=$(command -v gh); $TOOL hello",
        "TOOL=$(command -v gh) env; $TOOL hello",
        "TOOL=$(command -v gh); sh -c 'TOOL=echo; $TOOL hello'",
        "TOOL='$(command -v gh)'; $TOOL hello",
        "CMD='gh repo delete o/r --yes'; CMD='echo hello'; eval \"$CMD\"",
        "CMD='gh repo delete o/r --yes' env; eval \"$CMD\"",
        "cmd='gh repo delete o/r --yes'; eval \"$CMD\"",
        "eval \"$CMD\"; CMD='gh repo delete o/r --yes'",
        "CMD='gh repo delete o/r --yes'; sh -c 'CMD=echo; eval \"$CMD\"'",
        "CMD='echo gh repo delete'; eval \"$CMD\"",
        "CMD='printf gh'; sh -c \"$CMD\"",
        "CMD='printf /usr/local/bin/gh'; sh -c \"$CMD\"",
        "TOOL=gh; f(){ local TOOL=python; $TOOL --version; }; f",
        "echo '$(gh repo delete o/r --yes)'",
        "echo 'gh repo delete o/r --yes'",
        "printf '%s\\n' 'gh repo delete o/r --yes'",
        "if true; then echo gh; fi",
        "case gh in gh) echo ok;; esac",
        'for x in gh; do echo "$x"; done',
        'if true; then printf "gh repo delete"; fi',
    ),
)
def test_unrelated_dynamic_commands_are_not_labeled_as_github(tmp_path: Path, command: str) -> None:
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is None or "GitHub" not in match.action_class
