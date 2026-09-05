"""Structured rules and metadata for claude-tmux cleanup commands."""

from __future__ import annotations

from itertools import product

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant, ExecutableMatcher

# claude-tmux-cleanup tears down the tmux sessions a Claude Code agent team
# runs in. It is installed under its own name and as the `ctc` shortcut, and
# both are the same program.
_CLEANUP_EXECUTABLES = ("claude-tmux-cleanup", "ctc")
# Session selection. `--all` takes every session running Claude Code, `--every`
# takes every tmux session on the host including unrelated work.
#
# Only `-a` appears in the short forms: arguments are lower-cased before
# matching, so `-A` (the short `--every`) and `-a` are the same token here.
# Both select sessions for the same unattended kill, so the collapse can only
# widen this rule, never narrow it.
_SESSION_SELECTION_FLAGS = ("--all", "--every", "-a")
# Without --force the command stops on a terminal prompt before killing
# anything, and that prompt is the gate. Requiring it here is what separates an
# unattended teardown from an interactive one.
_FORCE_FLAGS = ("--force", "-f")
# --prune extends the same run past tmux: it kills Claude Code processes that
# hold a tty but sit in no live pane. That covers processes this run just
# orphaned and any that were already stray, so it reaches sessions the caller
# may never have listed.
_PRUNE_FLAGS = ("--prune", "-p")
# --dry-run prints the sessions and pids it would take and returns without
# signalling anything, so it is the documented preview for both rules.
_DRY_RUN_FLAGS = ("--dry-run", "-n")


def _cleanup_matcher(*required_flags: str) -> AnyMatcher:
    """Match either cleanup launcher carrying all of the given flags."""

    return AnyMatcher(
        matchers=tuple(
            executable_matcher(executable, required_flags=frozenset(required_flags))
            for executable in _CLEANUP_EXECUTABLES
        )
    )


def _cleanup_variants(*flag_groups: tuple[str, ...]) -> tuple[ExecutableMatcher, ...]:
    """Expand long and short spellings of each required flag into matchers."""

    return tuple(
        matcher for combination in product(*flag_groups) for matcher in _cleanup_matcher(*combination).matchers
    )


_CTC_SESSION_TEARDOWN = AnyMatcher(
    matchers=_cleanup_variants(_SESSION_SELECTION_FLAGS, _FORCE_FLAGS),
)
_CTC_PROCESS_PRUNE = AnyMatcher(
    matchers=_cleanup_variants(_PRUNE_FLAGS, _FORCE_FLAGS),
)
# The preview is the flag on its own: `ctc --all --force --prune --dry-run`
# kills nothing, so the safe variant does not restate the destructive flags it
# is previewing.
_CTC_DRY_RUN = AnyMatcher(matchers=_cleanup_variants(_DRY_RUN_FLAGS))


CLAUDE_TMUX_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "claude tmux session teardown command": ("destructive_shell",),
    "claude tmux process prune command": ("destructive_shell",),
}

CLAUDE_TMUX_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.claude-tmux.session-teardown",
        title="Claude tmux unattended session teardown",
        description=(
            "Identifies claude-tmux-cleanup runs that kill tmux sessions without the "
            "confirmation prompt. Every pane in a selected session is terminated, ending the "
            "agent teams running in them and discarding the unsaved terminal state they hold."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("claude tmux session teardown command",),
        safer_alternatives=(
            "Run the same command with --dry-run to list the sessions, or drop --force and confirm each one.",
        ),
        matcher=_CTC_SESSION_TEARDOWN,
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Claude tmux cleanup preview",
                matcher=_CTC_DRY_RUN,
            ),
        ),
        example_command="ctc --all --force",
    ),
    CommandSafetyRule(
        rule_id="command.claude-tmux.process-prune",
        title="Claude tmux unattended process prune",
        description=(
            "Identifies claude-tmux-cleanup runs that kill Claude Code processes outside tmux "
            "without the confirmation prompt. The scan runs after any session teardown in the "
            "same command, so it takes both the processes that teardown just orphaned and any "
            "that were already stray, including a Claude Code session started in a plain "
            "terminal that the caller never named."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("claude tmux process prune command",),
        safer_alternatives=("Run the same command with --dry-run to list the pids before signalling any of them.",),
        matcher=_CTC_PROCESS_PRUNE,
        safe_variants=(
            CommandSafeVariant(
                variant_id="dry-run",
                title="Claude tmux prune preview",
                matcher=_CTC_DRY_RUN,
            ),
        ),
        example_command="ctc --all --force --prune",
    ),
)

CLAUDE_TMUX_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.claude-tmux",
        name="Claude tmux cleanup protection",
        description="Reviews claude-tmux-cleanup runs that kill agent-team sessions or Claude Code processes.",
        action_classes=(
            "claude tmux session teardown command",
            "claude tmux process prune command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Use --dry-run to list the sessions and pids before killing anything.",),
        reference_urls=("https://github.com/s403o/claude-code-tmux",),
    ),
)
