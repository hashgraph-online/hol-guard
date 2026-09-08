"""Structured repo2nb command extension tests."""

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

REPO2NB_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "repo2nb reverse notebook.ipynb --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --output ./dest --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb -o ./dest --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --for",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --forc",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --fo",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --f",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb $FORCE_FLAG",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        'repo2nb reverse notebook.ipynb "$FORCE_FLAG"',
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb ${FORCE_FLAG}",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb $(echo --force)",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb `echo --force`",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --output $DEST --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb sync ./my-repo",
        "repo2nb notebook sync command",
        "command.repo2nb.sync",
    ),
    (
        "repo2nb sync ./my-repo --notebook project.ipynb",
        "repo2nb notebook sync command",
        "command.repo2nb.sync",
    ),
    (
        "repo2nb sync ./my-repo --unknown-flag --dry-run",
        "repo2nb notebook sync command",
        "command.repo2nb.sync",
    ),
)


def test_repo2nb_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations reach review and attribute to repo2nb rules."""

    for command, expected_rule in REPO2NB_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.repo2nb"}
        assert expected_rule in matched, command


REPO2NB_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("python3 -m repo2nb reverse notebook.ipynb --output ./dest --force", "command.repo2nb.reverse-force"),
    ("py -m repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("exec repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("xargs repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("xargs -n 1 repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("xargs -n 1 python -m repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("python -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("python3 -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("py -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("exec repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("xargs repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("xargs -n 1 python -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("exec repo2nb reverse notebook.ipynb $FORCE_FLAG", "command.repo2nb.reverse-force"),
    ("xargs -n 1 repo2nb reverse notebook.ipynb $FORCE_FLAG", "command.repo2nb.reverse-force"),
    ("python -m repo2nb reverse notebook.ipynb $(echo --force)", "command.repo2nb.reverse-force"),
    ("py -m repo2nb reverse notebook.ipynb ${FORCE_FLAG}", "command.repo2nb.reverse-force"),
)


def test_repo2nb_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in REPO2NB_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.repo2nb" for item in evaluation.extension_observations)


REPO2NB_SAFE_COMMANDS: tuple[str, ...] = (
    "repo2nb reverse notebook.ipynb",  # no --force: never reviewed, by design
    "repo2nb reverse notebook.ipynb --output ./dest",
    "repo2nb reverse ./notebooks/release-1.ipynb",  # plain paths stay unreviewed
    "repo2nb sync ./my-repo --dry-run",
    "repo2nb sync --dry-run",
    "repo2nb --help",
    "repo2nb reverse --help",
    "repo2nb sync --help",
)


def test_repo2nb_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(REPO2NB_SAFE_COMMANDS, tmp_path)


def test_repo2nb_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.repo2nb")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
