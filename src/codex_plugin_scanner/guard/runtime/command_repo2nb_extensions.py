"""Structured rules and metadata for the repo2nb command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

# Flag surface verified against repo2nb 0.2.1 (PyPI wheel, cli.py): `reverse`
# accepts --force (store_true, no -f alias) and --output/-o; `sync` accepts
# --notebook and --dry-run. Dispatch requires the literal subcommand as
# argv[0], so no global options can precede it. Module invocation
# (`python/-m repo2nb ...`) enforces the module name as literal subcommand
# tokens because option-value tracking does not retain `-m` values.
_REPO2NB_REVERSE_FORCE = AnyMatcher(
    matchers=(
        executable_matcher(
            "repo2nb",
            "reverse",
            required_flags=frozenset({"--force"}),
            options_with_values=frozenset({"--output", "-o"}),
        ),
        executable_matcher(
            "python",
            "-m",
            "repo2nb",
            "reverse",
            required_flags=frozenset({"--force"}),
            options_with_values=frozenset({"--output", "-o"}),
        ),
        executable_matcher(
            "python3",
            "-m",
            "repo2nb",
            "reverse",
            required_flags=frozenset({"--force"}),
            options_with_values=frozenset({"--output", "-o"}),
        ),
    )
)

_REPO2NB_SYNC = AnyMatcher(
    matchers=(
        executable_matcher(
            "repo2nb",
            "sync",
            options_with_values=frozenset({"--notebook"}),
        ),
        executable_matcher(
            "python",
            "-m",
            "repo2nb",
            "sync",
            options_with_values=frozenset({"--notebook"}),
        ),
        executable_matcher(
            "python3",
            "-m",
            "repo2nb",
            "sync",
            options_with_values=frozenset({"--notebook"}),
        ),
    )
)

REPO2NB_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.repo2nb.reverse-force",
        title="repo2nb forced notebook reversal",
        description=(
            "Identifies `repo2nb reverse --force`, which can overwrite an "
            "existing non-empty destination directory. A symlink inside the "
            "destination can cause writes to land outside the intended root "
            "even with --force's existing non-empty-directory check."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("repo2nb forced directory overwrite command",),
        safer_alternatives=(
            "Run repo2nb reverse without --force first and review what it reports about the existing directory.",
            "Confirm the destination path is not a sensitive system or home directory before forcing.",
        ),
        matcher=_REPO2NB_REVERSE_FORCE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _REPO2NB_REVERSE_FORCE,
                variant_id="help",
                title="repo2nb reverse command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.repo2nb.sync",
        title="repo2nb notebook sync",
        description=(
            "Identifies `repo2nb sync`, a one-directional repo-to-notebook "
            "sync that can silently drop manually-added notebook cells not "
            "tracked in .repo2nb/manifest.json."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("repo2nb notebook sync command",),
        safer_alternatives=(
            "Review .repo2nb/manifest.json to see which cells are tracked before syncing.",
            "Back up or export manually-added cells before running sync.",
        ),
        matcher=_REPO2NB_SYNC,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _REPO2NB_SYNC,
                variant_id="dry-run",
                title="repo2nb sync dry run",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _REPO2NB_SYNC,
                variant_id="help",
                title="repo2nb sync command help",
                flag="--help",
            ),
        ),
    ),
)

REPO2NB_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.repo2nb",
        name="repo2nb command protection",
        description=(
            "Reviews repo2nb commands that can overwrite an existing "
            "destination directory or silently drop untracked notebook "
            "cells."
        ),
        action_classes=(
            "repo2nb forced directory overwrite command",
            "repo2nb notebook sync command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run repo2nb reverse without --force first to see what it reports.",
            "Review the manifest before syncing to catch untracked manual edits.",
        ),
        reference_urls=("https://github.com/David-Magdy/repo2nb",),
    ),
)
