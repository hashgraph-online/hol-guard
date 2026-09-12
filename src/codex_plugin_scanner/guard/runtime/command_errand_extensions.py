"""Structured rules and metadata for the Errand command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import known_option_advance
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    _after_leading_options,
    _segment_matches_executable,
)

# CLI surface verified against Errand v0.4.2 (cmd/errand: main.go, run.go,
# run_config.go, fetch.go). Dispatch is on argv[1]: a known subcommand runs
# that subcommand; anything else is `errand [run options] -- COMMAND`, which
# executes COMMAND on the selected runner. Go's flag parser accepts one or two
# dashes, stops at the first operand, and treats -h/-help/--help as help.
#
# Conservative matching covers:
# - Launchers: errand, exec errand, xargs errand (with known leading options)
# - Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks) in the run
#   option prefix, which may expand to the job separator
# - Fail-secure option parsing: unknown run options cannot prove a job absent

_ERRAND_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("errand",),
    ("exec", "errand"),
    ("xargs", "errand"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})
_HELP_FLAGS: frozenset[str] = frozenset({"-h", "-help", "--help"})
_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "serve",
        "setup",
        "peers",
        "workspaces",
        "config",
        "access",
        "doctor",
        "attach",
        "push",
        "fetch",
        "ps",
        "status",
        "kill",
        "df",
        "gc",
        "version",
        "_automatic-apply",
        "_stdio",
    }
)


def _go_flags(*names: str) -> frozenset[str]:
    """Return both single- and double-dash spellings accepted by Go's flag package."""

    return frozenset(f"-{name}" for name in names) | frozenset(f"--{name}" for name in names)


_RUN_OPTIONS_WITH_VALUES = _go_flags(
    "on",
    "url",
    "where",
    "profile",
    "workdir",
    "w",
    "env",
    "e",
    "env-file",
    "passenv",
    "forward",
    "L",
    "artifact",
    "cache",
    "workspace",
    "workspace-root",
)
_RUN_FLAGS = _go_flags(
    "detach",
    "d",
    "no-forward",
    "apply",
    "no-apply",
    "no-artifacts",
    "no-caches",
    "no-env-files",
    "verbose",
    "v",
    "include-all",
    "no-snapshot",
)
_FETCH_OPTIONS_WITH_VALUES = _go_flags("on", "url", "output", "o")


@dataclass(frozen=True, slots=True)
class ErrandRunMatcher:
    """Match `errand [options] -- COMMAND`, which executes COMMAND on a runner.

    Known subcommands and help never match. A bare operand, an unresolved
    expansion, or an unknown option before the job separator cannot prove a
    job absent, so those match conservatively.
    """

    launchers: tuple[tuple[str, ...], ...] = _ERRAND_LAUNCHERS
    subcommands: frozenset[str] = _SUBCOMMANDS
    options_with_values: frozenset[str] = _RUN_OPTIONS_WITH_VALUES
    flags: frozenset[str] = _RUN_FLAGS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                arguments = segment.arguments
                if len(launcher) > 1:
                    arguments = _after_leading_options(arguments, self.leading_options_with_values, frozenset())
                    if arguments[:1] != launcher[1:]:
                        break
                    arguments = arguments[1:]
                if self._executes_job(arguments):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched Errand job execution arguments.",
                        )
                    )
                break
        return tuple(evidence)

    def _executes_job(self, arguments: tuple[str, ...]) -> bool:
        if not arguments or arguments[0] in self.subcommands:
            return False
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                return index + 1 < len(arguments)
            if token in _HELP_FLAGS:
                return False
            if not token.startswith("-") or any(marker in token for marker in self.expansion_markers):
                return True
            advance = known_option_advance(token, options_with_values=self.options_with_values, known_flags=self.flags)
            if advance is None:
                return True
            index += advance
        return False


_ERRAND_FETCH_APPLY = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "fetch",
            required_flags=frozenset({apply_flag}),
            options_with_values=_FETCH_OPTIONS_WITH_VALUES,
            allow_leading_options=len(launcher) > 1,
            leading_options_with_values=(_WRAPPER_LEADING_OPTIONS_WITH_VALUES if len(launcher) > 1 else frozenset()),
            fail_secure_unknown_options=True,
        )
        for launcher in _ERRAND_LAUNCHERS
        for apply_flag in ("--apply", "-apply")
    )
)

ERRAND_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.errand.run",
        title="Errand job execution",
        description=(
            "Identifies `errand [options] -- COMMAND`, which executes COMMAND on the "
            "selected runner, may upload a working-tree snapshot, and may apply "
            "retained changes to the originating checkout after success."
        ),
        severity="high",
        risk_classes=("execution", "network_egress", "destructive_shell"),
        action_classes=("Errand execution command",),
        safer_alternatives=(
            "Review the selected runner, snapshot scope, forwarded environment, and command before submission.",
            "Use --no-apply to keep retained changes out of the originating checkout until explicitly applied.",
        ),
        matcher=ErrandRunMatcher(),
        default_mode="review",
        example_command="errand --on linux -- make test",
    ),
    CommandSafetyRule(
        rule_id="command.errand.fetch-apply",
        title="Errand retained-change application",
        description=(
            "Identifies `errand fetch --apply HANDLE`, which merges retained runner changes "
            "into the originating checkout."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Errand checkout apply command",),
        safer_alternatives=(
            "Run errand fetch HANDLE to stage retained changes for inspection before applying them.",
            "Check errand status HANDLE and review the destination checkout before applying retained changes.",
        ),
        matcher=_ERRAND_FETCH_APPLY,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _ERRAND_FETCH_APPLY,
                variant_id="help",
                title="Errand fetch command help",
                flag="--help",
            ),
        ),
        example_command="errand fetch --apply linux/job",
    ),
)

ERRAND_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.errand",
        name="Errand command protection",
        description=(
            "Requires Errand 0.4.2 or later. Reviews execution and checkout apply; "
            "ps, status, and doctor remain automatic."
        ),
        action_classes=("Errand execution command", "Errand checkout apply command"),
        risk_classes=("execution", "network_egress", "destructive_shell"),
        safer_alternatives=(
            "Inspect jobs with errand ps or errand status HANDLE before executing or applying changes.",
            "Stage retained changes with errand fetch HANDLE before applying them.",
        ),
        reference_urls=(
            "https://github.com/lydakis/errand",
            "https://github.com/lydakis/errand/blob/main/docs/USAGE.md",
        ),
        executables=("errand",),
    ),
)
