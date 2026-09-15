"""Structured simgit command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

_EXTENSION_ID = "command.simgit"
_DISCARD_DIRTY = "command.simgit.discard-dirty"
_DELETE_UNMERGED = "command.simgit.delete-unmerged"
_DISCARD_ACTION = "simgit uncommitted worktree discard command"
_UNMERGED_ACTION = "simgit unmerged branch deletion command"

SIMGIT_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    # --discard-dirty deletes uncommitted and untracked files that live outside
    # the source repository, on both subcommands that accept it.
    ("simgit remove /tmp/agent-work --discard-dirty", _DISCARD_ACTION, _DISCARD_DIRTY),
    ("simgit gc --discard-dirty", _DISCARD_ACTION, _DISCARD_DIRTY),
    ("sg remove /tmp/agent-work --discard-dirty", _DISCARD_ACTION, _DISCARD_DIRTY),
    # The global --json flag is accepted before or after the subcommand.
    ("simgit --json remove /tmp/agent-work --discard-dirty", _DISCARD_ACTION, _DISCARD_DIRTY),
    ("simgit gc --json --discard-dirty --older-than 0s", _DISCARD_ACTION, _DISCARD_DIRTY),
    # Reordered flags and companion flags preserve meaning.
    ("simgit remove --discard-dirty /tmp/agent-work", _DISCARD_ACTION, _DISCARD_DIRTY),
    ("simgit gc --include-persistent --discard-dirty --prefix agent/", _DISCARD_ACTION, _DISCARD_DIRTY),
    # Quoting and paths with spaces.
    ('simgit remove "/tmp/agent work" --discard-dirty', _DISCARD_ACTION, _DISCARD_DIRTY),
    # An unknown option must not hide the destructive flag.
    ("simgit remove /tmp/agent-work --not-a-real-flag --discard-dirty", _DISCARD_ACTION, _DISCARD_DIRTY),
    # --delete-unmerged deletes a branch past Git's merged check.
    ("simgit remove agent/1234 --delete-branch --delete-unmerged", _UNMERGED_ACTION, _DELETE_UNMERGED),
    ("simgit gc --delete-branches --delete-unmerged", _UNMERGED_ACTION, _DELETE_UNMERGED),
    ("sg gc --delete-branches --delete-unmerged --prefix agent/", _UNMERGED_ACTION, _DELETE_UNMERGED),
    # Both destructive flags on one invocation keep both rules.
    ("simgit gc --discard-dirty --delete-branches --delete-unmerged", _DISCARD_ACTION, _DISCARD_DIRTY),
    ("simgit gc --discard-dirty --delete-branches --delete-unmerged", _UNMERGED_ACTION, _DELETE_UNMERGED),
)

SIMGIT_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("exec simgit remove /tmp/agent-work --discard-dirty", _DISCARD_DIRTY),
    ("exec sg gc --discard-dirty", _DISCARD_DIRTY),
    ("xargs simgit remove /tmp/agent-work --discard-dirty", _DISCARD_DIRTY),
    ("xargs -n 1 simgit gc --delete-branches --delete-unmerged", _DELETE_UNMERGED),
    ("xargs -n 1 sg remove agent/1234 --delete-branch --delete-unmerged", _DELETE_UNMERGED),
    ("simgit list --json && simgit gc --discard-dirty", _DISCARD_DIRTY),
    ("simgit list --json | simgit gc --delete-branches --delete-unmerged", _DELETE_UNMERGED),
)

SIMGIT_UNMATCHED_COMMANDS: tuple[str, ...] = (
    # Documented safe counterpart of every reviewed shape: the same command
    # without the destructive flag, which simgit refuses to run destructively.
    "simgit remove /tmp/agent-work",
    "simgit remove agent/1234 --delete-branch",
    "simgit gc",
    "simgit gc --older-than 7d --prefix agent/ --delete-branches",
    # gc previews the exact destructive selection without acting on it.
    "simgit gc --discard-dirty --dry-run",
    "simgit gc --delete-branches --delete-unmerged --dry-run",
    "simgit gc --discard-dirty --delete-branches --delete-unmerged --dry-run",
    # Non-destructive subcommands, including the ones a harness runs constantly.
    "simgit doctor --json",
    "simgit list --json",
    "simgit add agent/1234 --path /tmp/agent-work --ephemeral",
    "simgit unlock /tmp/agent-work",
    "simgit prune --all",
    "simgit repair",
    # run's child argv is judged by Guard's existing command handling.
    "simgit run agent/1234 -- pytest -x",
    # The destructive flag names appear as option values, not as flags.
    'simgit remove /tmp/agent-work --commit -m "--discard-dirty"',
    "simgit gc --prefix --discard-dirty",
    # Help output for the reviewed commands.
    "simgit remove --help",
    "simgit gc --help",
    "simgit remove /tmp/agent-work --discard-dirty --help",
)


def _effective_rule_ids(command: str, tmp_path: Path) -> set[str]:
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    )
    return {
        item.rule.rule_id
        for item in observations
        if item.extension.extension_id == _EXTENSION_ID and item.effective_evidence
    }


def test_simgit_destructive_flags_reach_extension_review(tmp_path: Path) -> None:
    """Every work-destroying flag is matched and attributed to its action class."""

    failures: list[str] = []
    for command, action_class, rule_id in SIMGIT_REVIEW_CASES:
        matched = _effective_rule_ids(command, tmp_path)
        rule = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
        owned = {item.rule_id: item.action_classes for item in rule.rules} if rule is not None else {}
        if rule_id not in matched or action_class not in owned.get(rule_id, ()):
            failures.append(f"{command!r}: matched={sorted(matched)!r}, expected {rule_id!r}/{action_class!r}")
    assert not failures, "\n".join(failures)


def test_simgit_wrapper_and_compound_invocations_reach_review(tmp_path: Path) -> None:
    """Wrappers, separators, and pipelines preserve the destructive meaning."""

    failures: list[str] = []
    for command, rule_id in SIMGIT_WRAPPER_REVIEW_COMMANDS:
        matched = _effective_rule_ids(command, tmp_path)
        if rule_id not in matched:
            failures.append(f"{command!r}: matched={sorted(matched)!r}, expected {rule_id!r}")
    assert not failures, "\n".join(failures)


def test_simgit_safe_counterparts_and_previews_stay_unmatched(tmp_path: Path) -> None:
    """Refusing defaults, previews, help, and option values never reach review."""

    failures: list[str] = []
    for command in SIMGIT_UNMATCHED_COMMANDS:
        matched = _effective_rule_ids(command, tmp_path)
        if matched:
            failures.append(f"{command!r}: unexpectedly matched {sorted(matched)!r}")
    assert not failures, "\n".join(failures)


def test_simgit_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in SIMGIT_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != _EXTENSION_ID for item in evaluation.extension_observations)


def test_simgit_nondestructive_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SIMGIT_UNMATCHED_COMMANDS, tmp_path)


def test_simgit_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
