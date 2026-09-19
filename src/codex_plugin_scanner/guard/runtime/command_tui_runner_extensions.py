"""Opt-in TUI Runner forced-reconfiguration protection.

TUI Runner is a local ratatui process orchestrator: after launch, every mutating
action it takes (killing processes bound to configured ports, scaffolding a new
project, spawning configured dev commands) is driven entirely through in-process
keyboard menu selections rather than separate argv-level subcommands. Guard's
command hook only observes the shell command an agent adapter passes to it before
execution, so those interactive actions are not visible here and are out of scope
for this extension. The one argv-level flag that changes behavior without further
interactive confirmation is --reconfigure, which forces the setup wizard to run and
unconditionally overwrites any existing tui.config.json for the chosen project once
the wizard completes.

Conservative matching covers:
- Standard launcher variants: tui-runner, tui-runner.exe, tui-runner.cmd
- Shell wrappers: exec tui-runner ..., xargs tui-runner ...
- Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks) that may supply
  --reconfigure and so cannot be proven absent.
"""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    ExecutableMatcher,
    _after_leading_options,
    _segment_matches_executable,
)

_TUI_RUNNER_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("tui-runner",),
    ("exec", "tui-runner"),
    ("xargs", "tui-runner"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})


def _tui_runner_launcher_matcher(launcher: tuple[str, ...]) -> ExecutableMatcher:
    is_wrapper = launcher[0] in ("exec", "xargs")
    return ExecutableMatcher(
        executables=executable_names(launcher[0]),
        subcommands=launcher[1:],
        required_flags=frozenset({"--reconfigure"}),
        required_flags_in_all_arguments=True,
        allow_leading_options=is_wrapper,
        leading_options_with_values=(_WRAPPER_LEADING_OPTIONS_WITH_VALUES if is_wrapper else frozenset()),
    )


_TUI_RUNNER_RECONFIGURE = AnyMatcher(
    matchers=tuple(_tui_runner_launcher_matcher(launcher) for launcher in _TUI_RUNNER_LAUNCHERS)
)


@dataclass(frozen=True, slots=True)
class TuiRunnerUnresolvedExpansionMatcher:
    """Match TUI Runner invocations whose flags may be supplied by shell expansion.

    A `$VAR`, `${VAR}`, `$(...)`, or backtick token can expand to --reconfigure
    at execution time, so its presence in a TUI Runner invocation means the
    destructive flag cannot be proven absent.
    """

    launchers: tuple[tuple[str, ...], ...] = _TUI_RUNNER_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, executable_names(launcher[0])):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in ("exec", "xargs"):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                prefix_positions = tuple(executable_names(token) for token in launcher[1:])
                if len(candidate_arguments) < len(prefix_positions) or any(
                    candidate_arguments[position] not in names for position, names in enumerate(prefix_positions)
                ):
                    continue
                remaining_arguments = candidate_arguments[len(prefix_positions) :]
                if any(
                    any(marker in argument for marker in self.expansion_markers) for argument in remaining_arguments
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched TUI Runner arguments that may expand to --reconfigure.",
                        )
                    )
                break
        return tuple(evidence)


def tui_runner_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for the TUI Runner expansion matcher."""

    if not isinstance(matcher, TuiRunnerUnresolvedExpansionMatcher):
        return None
    executables = frozenset().union(*(executable_names(launcher[0]) for launcher in matcher.launchers))
    keywords = frozenset(launcher[1] for launcher in matcher.launchers if len(launcher) > 1)
    return executables, keywords


_TUI_RUNNER_RECONFIGURE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_TUI_RUNNER_RECONFIGURE.matchers, TuiRunnerUnresolvedExpansionMatcher()),
)

TUI_RUNNER_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.tui-runner.reconfigure",
        example_command="tui-runner --reconfigure",
        title="TUI Runner forced reconfiguration",
        description=(
            "Identifies TUI Runner invocations with --reconfigure, which forces the setup wizard to "
            "run and unconditionally overwrites any existing tui.config.json for the chosen project "
            "once the wizard completes. Invocations carrying unresolved shell expansions are reviewed "
            "because they cannot prove --reconfigure absent."
        ),
        matcher=_TUI_RUNNER_RECONFIGURE_WITH_EXPANSIONS,
        action_classes=("tui-runner forced reconfiguration command",),
        safer_alternatives=(
            "Inspect the project's existing tui.config.json before forcing --reconfigure, since the "
            "wizard replaces it without a separate confirmation step.",
            "Expand shell variables and command substitutions before running tui-runner --reconfigure.",
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        compatibility_fallback=True,
    ),
)

TUI_RUNNER_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.tui-runner",
        name="TUI Runner forced reconfiguration protection",
        description=(
            "Reviews TUI Runner --reconfigure invocations, which overwrite a project's saved process "
            "configuration. Port cleanup, process spawning, and project scaffolding happen through "
            "TUI Runner's interactive menu after launch and are not observable command-line events, "
            "so this extension does not cover them."
        ),
        action_classes=("tui-runner forced reconfiguration command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Review the saved tui.config.json before forcing a reconfiguration that will replace it.",),
        reference_urls=(),
    ),
)
