"""Structured agi-memory command extension tests."""

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

AGI_MEMORY_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "agi-memory sync dedupe",
        "agi-memory vault rewrite command",
        "command.agi-memory.sync-dedupe",
    ),
    # agent-memory is an exact alias console script, not a legacy spelling:
    # both names ship in every install, so a rule that misses one is bypassed
    # by typing the other.
    (
        "agent-memory sync dedupe",
        "agi-memory vault rewrite command",
        "command.agi-memory.sync-dedupe",
    ),
    (
        "agi-memory sync $ACTION",
        "agi-memory vault rewrite command",
        "command.agi-memory.sync-dedupe",
    ),
    (
        "agi-memory sync $(echo dedupe)",
        "agi-memory vault rewrite command",
        "command.agi-memory.sync-dedupe",
    ),
    (
        "agi-memory delete 3 --hard",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete #3 --hard",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete --hard 3",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    # argparse resolves unambiguous long-option prefixes. --ha is the shortest
    # prefix that means --hard; --h stays ambiguous with argparse's own --help.
    (
        "agi-memory delete 3 --har",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete 3 --ha",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agent-memory delete 3 --hard",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete 3 $FLAGS",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        'agi-memory delete 3 "$FLAGS"',
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete 3 ${FLAGS}",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory delete 3 `echo --hard`",
        "agi-memory permanent memory deletion command",
        "command.agi-memory.delete-hard",
    ),
    (
        "agi-memory pin tls-rule 'TLS v1.3 only'",
        "agi-memory core memory pin command",
        "command.agi-memory.pin",
    ),
    (
        "agi-memory pin tls-rule 'TLS v1.3 only' --category architecture",
        "agi-memory core memory pin command",
        "command.agi-memory.pin",
    ),
    (
        "agi-memory pin tls-rule 'TLS v1.3 only' -p my-app",
        "agi-memory core memory pin command",
        "command.agi-memory.pin",
    ),
    (
        "agent-memory pin tls-rule 'TLS v1.3 only'",
        "agi-memory core memory pin command",
        "command.agi-memory.pin",
    ),
    (
        "agi-memory unpin tls-rule",
        "agi-memory core memory unpin command",
        "command.agi-memory.unpin",
    ),
    (
        "agent-memory unpin tls-rule",
        "agi-memory core memory unpin command",
        "command.agi-memory.unpin",
    ),
)

AGI_MEMORY_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m agi_memory.mcp_server sync dedupe", "command.agi-memory.sync-dedupe"),
    ("python3 -m agi_memory.mcp_server sync dedupe", "command.agi-memory.sync-dedupe"),
    ("py -m agi_memory.mcp_server sync dedupe", "command.agi-memory.sync-dedupe"),
    ("exec agi-memory sync dedupe", "command.agi-memory.sync-dedupe"),
    ("exec agent-memory sync dedupe", "command.agi-memory.sync-dedupe"),
    ("xargs agi-memory sync dedupe", "command.agi-memory.sync-dedupe"),
    ("xargs -n 1 agi-memory sync dedupe", "command.agi-memory.sync-dedupe"),
    ("xargs -n 1 python -m agi_memory.mcp_server sync dedupe", "command.agi-memory.sync-dedupe"),
    ("python -m agi_memory.mcp_server delete 3 --hard", "command.agi-memory.delete-hard"),
    ("exec agi-memory delete 3 --hard", "command.agi-memory.delete-hard"),
    ("xargs -n 1 agi-memory delete 3 --hard", "command.agi-memory.delete-hard"),
    ("exec agi-memory delete 3 $FLAGS", "command.agi-memory.delete-hard"),
    ("xargs -n 1 agi-memory delete 3 ${FLAGS}", "command.agi-memory.delete-hard"),
    ("python -m agi_memory.mcp_server pin k 'v'", "command.agi-memory.pin"),
    ("exec agi-memory unpin k", "command.agi-memory.unpin"),
    ("xargs agent-memory unpin k", "command.agi-memory.unpin"),
)

AGI_MEMORY_COMPOUND_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("agi-memory sync status && agi-memory sync dedupe", "command.agi-memory.sync-dedupe"),
    ("agi-memory log; agi-memory delete 3 --hard", "command.agi-memory.delete-hard"),
    ("agi-memory blocks | grep tls && agi-memory unpin tls-rule", "command.agi-memory.unpin"),
)


def test_agi_memory_destructive_commands_reach_review(tmp_path: Path) -> None:
    """Every destructive form matches its owning rule under the agi-memory extension."""

    failures: list[str] = []
    for command, _action_class, expected_rule in AGI_MEMORY_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agi-memory"}
        if expected_rule not in matched:
            failures.append(f"{command!r}: matched {sorted(matched)!r}, expected {expected_rule!r}")
    assert not failures, "\n".join(failures)


def test_agi_memory_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations attribute to agi-memory rules."""

    for command, expected_rule in AGI_MEMORY_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agi-memory"}
        assert expected_rule in matched, command


def test_agi_memory_compound_commands_retain_destructive_evidence(tmp_path: Path) -> None:
    """A safe read in the same line never masks the destructive segment."""

    for command, expected_rule in AGI_MEMORY_COMPOUND_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agi-memory"}
        assert expected_rule in matched, command


def test_agi_memory_action_classes_stay_owned_by_the_extension(tmp_path: Path) -> None:
    """Declared action classes match what the rules actually emit."""

    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.agi-memory")
    assert extension is not None
    declared = set(extension.action_classes)
    for _command, action_class, _rule_id in AGI_MEMORY_REVIEW_CASES:
        assert action_class in declared, action_class


def test_agi_memory_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in AGI_MEMORY_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.agi-memory" for item in evaluation.extension_observations)


AGI_MEMORY_SAFE_COMMANDS: tuple[str, ...] = (
    # Reads: gating these would put a prompt in front of every lookup.
    "agi-memory recall 'why sqlite'",
    "agi-memory recall 'why sqlite' --deep",
    "agi-memory log",
    "agi-memory log --limit 20",
    "agi-memory inspect 3",
    "agi-memory inspect #3",
    "agi-memory blocks",
    "agi-memory timeline",
    "agi-memory structure src/",
    "agi-memory callers verify_token",
    "agi-memory dependencies verify_token",
    "agi-memory impact src/auth.py",
    "agent-memory log",
    "agent-memory blocks",
    # sync dispatches on a literal positional: only status/now/dedupe/init reach
    # the sync module, and only dedupe rewrites the vault.
    "agi-memory sync status",
    "agent-memory sync status",
    # A soft delete marks the observation superseded and is reversible.
    "agi-memory delete 3",
    "agi-memory delete #3",
    # Help output for every reviewed operation stays side-effect free.
    "agi-memory --help",
    "agi-memory delete --help",
    "agi-memory pin --help",
    "agi-memory unpin --help",
    "agi-memory sync --help",
)


def test_agi_memory_read_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(AGI_MEMORY_SAFE_COMMANDS, tmp_path)


def test_agi_memory_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.agi-memory")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
