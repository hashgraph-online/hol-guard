"""Structured rules and metadata for claude-tmux cleanup commands."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import final

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule, CommandSafeVariant, ExecutableMatcher

# claude-tmux-cleanup tears down the tmux sessions a Claude Code agent team
# runs in. It is installed under its own name and as the `ctc` shortcut, and
# both are the same program.
_CLEANUP_EXECUTABLES = ("claude-tmux-cleanup", "ctc")
# Every kill in this tool is gated by one confirmation prompt, and --force is
# what removes it. It is not paired with a session selection flag: with no
# target and no selection the tool falls into its interactive sweep, where
# --force answers the per-session prompt affirmatively for every session on the
# host. So `ctc --force` kills more than `ctc --all --force` does, and the force
# flag alone is the signal. Selection flags and session operands only narrow the
# blast radius.
_FORCE_FLAGS = ("--force", "-f")
# --prune extends the same run past tmux: it kills Claude Code processes that
# hold a tty but sit in no live pane. That covers processes this run just
# orphaned and any that were already stray, so it reaches sessions the caller
# may never have listed.
_PRUNE_FLAGS = ("--prune", "-p")
# --dry-run prints the sessions and pids it would take and returns without
# signalling anything, so it is the documented preview for both rules.
_DRY_RUN_FLAGS = ("--dry-run", "-n")
# Help exits before the tool reads a session list, so it never reaches a prompt
# to answer or a process to signal.
_HELP_FLAGS = frozenset({"--help", "-h"})


def _cleanup_matcher(*required_flags: str) -> tuple[ExecutableMatcher, ...]:
    """Match either cleanup launcher carrying all of the given flags."""

    return tuple(
        executable_matcher(
            executable,
            required_flags=frozenset(required_flags),
            forbidden_flags=_HELP_FLAGS,
        )
        for executable in _CLEANUP_EXECUTABLES
    )


def _cleanup_variants(*flag_groups: tuple[str, ...]) -> tuple[ExecutableMatcher, ...]:
    """Expand long and short spellings of each required flag into matchers."""

    return tuple(matcher for combination in product(*flag_groups) for matcher in _cleanup_matcher(*combination))


# The prompt reads one line from standard input and treats `y` or `yes` as
# consent, so a pipeline that feeds it either one is as unattended as --force.
# `yes` with no operand repeats `y` forever, which is the documented way to
# answer a prompt loop; `yes n` refuses and is not consent.
_AFFIRMATIVE_FEEDERS = frozenset({"yes", "echo", "printf"})
_AFFIRMATIVE_VALUES = frozenset({"y", "yes", "y\n", "yes\n", "y\\n", "yes\\n"})


def _feeds_affirmative_input(segment_executable: str | None, arguments: tuple[str, ...]) -> bool:
    """Report whether one pipeline segment answers a yes/no prompt with consent."""

    if segment_executable is None:
        return False
    name = segment_executable.rsplit("/", 1)[-1].lower()
    if name not in _AFFIRMATIVE_FEEDERS:
        return False
    operands = tuple(argument for argument in arguments if not argument.startswith("-"))
    if not operands:
        # Bare `yes` emits an endless stream of `y`; bare `echo`/`printf` emit
        # nothing a prompt would read as consent.
        return name == "yes"
    return all(operand.strip().strip("'\"").lower() in _AFFIRMATIVE_VALUES for operand in operands)


@final
@dataclass(frozen=True, slots=True)
class ConfirmationFedMatcher:
    """Match a segment whose confirmation prompt is answered by an earlier pipe.

    The declared matcher decides what the fed segment must look like. This adds
    the one structural condition the flag matchers cannot express: an earlier
    stage of the *same* pipeline supplies the consent the prompt asks for.
    Segments joined by ``&&`` or ``;`` run in their own execution context and
    share no standard input, so they are not a feed.
    """

    matcher: AnyMatcher

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        fed_contexts = {
            (segment.execution_context, segment.pipeline_index)
            for segment in command.segments
            if _feeds_affirmative_input(segment.executable, segment.arguments)
        }
        if not fed_contexts:
            return ()
        evidence = tuple(
            item
            for item in self.matcher.match(command)
            if any(
                context == command.segments[item.segment_index].execution_context
                and index < command.segments[item.segment_index].pipeline_index
                for context, index in fed_contexts
            )
        )
        return evidence


# Any cleanup run that is not a preview or a help request reaches the prompt, so
# a fed pipeline needs no flag of its own to be a kill.
_CTC_ANY_RUN = AnyMatcher(matchers=_cleanup_matcher())
_CTC_ANY_PRUNE = AnyMatcher(matchers=_cleanup_variants(_PRUNE_FLAGS))

_CTC_SESSION_TEARDOWN = AnyMatcher(
    matchers=(
        *_cleanup_variants(_FORCE_FLAGS),
        ConfirmationFedMatcher(matcher=_CTC_ANY_RUN),
    ),
)
_CTC_PROCESS_PRUNE = AnyMatcher(
    matchers=(
        *_cleanup_variants(_PRUNE_FLAGS, _FORCE_FLAGS),
        ConfirmationFedMatcher(matcher=_CTC_ANY_PRUNE),
    ),
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
            "Identifies claude-tmux-cleanup runs that kill tmux sessions without answering the "
            "confirmation prompt by hand — either --force, or a pipeline feeding the prompt its "
            "consent. Every pane in a selected session is terminated, ending the agent teams "
            "running in them and discarding the unsaved terminal state they hold. With no "
            "target and no selection flag the run sweeps every session on the host."
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
            "without answering the confirmation prompt by hand. The scan runs after any session "
            "teardown in the same command, so it takes both the processes that teardown just "
            "orphaned and any that were already stray, including a Claude Code session started "
            "in a plain terminal that the caller never named."
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
