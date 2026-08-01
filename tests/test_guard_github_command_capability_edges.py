from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.github_capability_contract import GitHubCommandCapability
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.github_routine_merge import is_routine_squash_merge
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request

PR_MERGE_ADMIN_CAPABILITY_CASES: tuple[tuple[str, tuple[str, ...], tuple[GitHubCommandCapability, ...]], ...] = (
    ("admin-001", ("pr", "merge", "123", "--squash"), ("routine_merge_remote",)),
    ("admin-002", ("pr", "merge", "123", "--admin"), ("admin_merge_remote",)),
    ("admin-003", ("pr", "merge", "123", "--admin", "--delete-branch"), ("admin_merge_remote", "delete_remote")),
    ("admin-004", ("pr", "merge", "123", "--admin=true"), ("admin_merge_remote",)),
    ("admin-005", ("pr", "merge", "123", "--admin=1"), ("admin_merge_remote",)),
    ("admin-006", ("pr", "merge", "123", "--admin=false"), ("merge_remote",)),
    ("admin-007", ("pr", "merge", "123", "--admin=0"), ("merge_remote",)),
    ("admin-008", ("pr", "merge", "123", "--admin=maybe"), ("unknown",)),
    ("admin-009", ("pr", "merge", "123", "--adminx"), ("merge_remote",)),
    ("admin-010", ("pr", "merge", "123", "--", "--admin"), ("merge_remote",)),
    ("routine-001", ("pr", "merge", "0", "--squash"), ("merge_remote",)),
    ("routine-002", ("pr", "merge", "123", "--squash", "--auto"), ("merge_remote",)),
    ("routine-003", ("pr", "merge", "123", "--squash", "--delete-branch"), ("merge_remote", "delete_remote")),
    ("routine-004", ("pr", "merge", "$PR", "--squash"), ("merge_remote",)),
    (
        "routine-005",
        ("pr", "merge", "4751", "--repo", "example/project", "--squash"),
        ("routine_merge_remote",),
    ),
    (
        "routine-006",
        ("pr", "merge", "4751", "--repo", "$REPOSITORY", "--squash"),
        ("merge_remote",),
    ),
    (
        "routine-007",
        ("pr", "merge", "4751", "--repo", "example/project", "--squash", "--admin"),
        ("admin_merge_remote",),
    ),
    (
        "routine-008",
        ("pr", "merge", "4751", "--repo", "example/project", "--squash", "--delete-branch"),
        ("merge_remote", "delete_remote"),
    ),
)


def test_pr_merge_admin_capability_matches_github_boolean_option_semantics() -> None:
    for case_id, args, expected_capabilities in PR_MERGE_ADMIN_CAPABILITY_CASES:
        actual_capabilities = classify_github_cli(args).capabilities
        assert actual_capabilities == expected_capabilities, (
            f"{case_id}: {args!r}; expected {expected_capabilities!r}, got {actual_capabilities!r}"
        )


def test_routine_squash_merge_rejects_unbounded_numeric_pull_request() -> None:
    assert is_routine_squash_merge(("18446744073709551615", "--squash"))
    assert not is_routine_squash_merge(("1" * 21, "--squash"))
    assert classify_github_cli(("pr", "merge", "1" * 100_000, "--squash")).capabilities == ("merge_remote",)


UNRELATED_DYNAMIC_COMMAND_CASES = (
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
)


def test_unrelated_dynamic_commands_are_not_labeled_as_github(tmp_path: Path) -> None:
    for case_id, command in enumerate(UNRELATED_DYNAMIC_COMMAND_CASES, start=1):
        match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)
        assert match is None or "GitHub" not in match.action_class, f"dynamic-safe-{case_id:03}: {command!r}"
