"""Structured rules and metadata for the Errand command safety extension."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import known_option_advance
from .command_rules import CommandSafetyRule, _segment_matches_executable
from .command_tokens import executable_name

# CLI surface verified against Errand v0.4.2 (cmd/errand: main.go, run.go,
# run_config.go, fetch.go). Dispatch is on argv[1]: a known subcommand runs
# that subcommand; anything else is `errand [run options] -- COMMAND`, which
# executes COMMAND on the selected runner. Go's flag parser accepts one or two
# dashes, stops at the first operand, gives a repeated boolean flag its last
# value, accepts strconv.ParseBool spellings, and treats -h/-help as help.
#
# Conservative matching covers:
# - Launchers: errand, exec errand, xargs errand, with known wrapper options
# - Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks, globs) that
#   may expand to the job separator or to --apply
# - Fail-secure option parsing: an unknown Errand or wrapper option cannot
#   prove a job or an apply absent

_ERRAND_EXECUTABLES = executable_names("errand")
_WRAPPER_EXECUTABLES: frozenset[str] = frozenset({"exec", "xargs"})
# Only wrapper options with append-only argv semantics are consumed. Replacement
# options (-I, -i, -J, --replace) and unknown options leave the launcher uncertain.
_WRAPPER_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {
        "-a",
        "-d",
        "-E",
        "-n",
        "-L",
        "-P",
        "-s",
        "-R",
        "-S",
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-lines",
        "--max-procs",
        "--max-chars",
        "--process-slot-var",
    }
)
_WRAPPER_FLAGS: frozenset[str] = frozenset(
    {
        "-0",
        "-c",
        "-l",
        "-r",
        "-t",
        "-p",
        "-x",
        "-o",
        "--null",
        "--no-run-if-empty",
        "--verbose",
        "--interactive",
        "--exit",
        "--open-tty",
    }
)
# Characters that can expand to an option at execution time. Tilde is omitted
# because it only ever expands to a path.
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`", "*", "?", "[", "{"})
_HELP_NAMES: frozenset[str] = frozenset({"h", "help"})
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
_RUN_OPTIONS_WITH_VALUES: frozenset[str] = frozenset(
    {
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
    }
)
_RUN_FLAGS: frozenset[str] = frozenset(
    {
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
    }
)
_FETCH_OPTIONS_WITH_VALUES: frozenset[str] = frozenset({"on", "url", "output", "o"})
_FETCH_FLAGS: frozenset[str] = frozenset({"apply", "conflicts", "json"})
# strconv.ParseBool spellings, which differ from generic CLI truthiness.
_GO_TRUE: frozenset[str] = frozenset({"1", "t", "T", "true", "True", "TRUE"})
_GO_FALSE: frozenset[str] = frozenset({"0", "f", "F", "false", "False", "FALSE"})


def _may_expand(token: str) -> bool:
    return any(marker in token for marker in _EXPANSION_MARKERS)


def _go_option(token: str) -> tuple[str, bool, str] | None:
    """Split one Go-style option into (name, has_value, value); None for operands."""

    if token == "-" or token == "--" or not token.startswith("-"):
        return None
    stripped = token[2:] if token.startswith("--") else token[1:]
    name, separator, value = stripped.partition("=")
    return name, bool(separator), value


@dataclass(frozen=True, slots=True)
class ErrandCommandMatcher:
    """Match Errand job execution or checkout apply from canonical argv.

    Known subcommands and help never match. A bare operand before the job
    separator, an unresolved expansion, or an unknown Errand or wrapper option
    cannot prove the protected operation absent, so those match conservatively.
    """

    operation: Literal["run", "fetch-apply"]
    subcommands: frozenset[str] = _SUBCOMMANDS
    run_options_with_values: frozenset[str] = _RUN_OPTIONS_WITH_VALUES
    run_flags: frozenset[str] = _RUN_FLAGS
    fetch_options_with_values: frozenset[str] = _FETCH_OPTIONS_WITH_VALUES
    fetch_flags: frozenset[str] = _FETCH_FLAGS
    wrapper_options_with_values: frozenset[str] = _WRAPPER_OPTIONS_WITH_VALUES
    wrapper_flags: frozenset[str] = _WRAPPER_FLAGS
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            if _segment_matches_executable(segment, _ERRAND_EXECUTABLES):
                arguments: tuple[str, ...] | None = segment.arguments
            elif _segment_matches_executable(segment, _WRAPPER_EXECUTABLES):
                arguments = self._wrapped_errand_arguments(segment.arguments)
            else:
                continue
            if arguments is None or self._requires_review(arguments):
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable,
                        detail="Matched Errand command boundary.",
                    )
                )
        return tuple(evidence)

    def _wrapped_errand_arguments(self, arguments: tuple[str, ...]) -> tuple[str, ...] | None:
        """Return Errand's argv after known wrapper options; None when uncertain.

        Uncertainty is only reported when a token names Errand, so wrappers
        launching other tools stay unmatched.
        """

        names_errand = any(executable_name(token) in _ERRAND_EXECUTABLES for token in arguments)
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                index += 1
                break
            if not token.startswith("-") or token == "-":
                break
            if _may_expand(token):
                return None if names_errand else ()
            advance = known_option_advance(
                token, options_with_values=self.wrapper_options_with_values, known_flags=self.wrapper_flags
            )
            if advance is None or index + advance > len(arguments):
                return None if names_errand else ()
            index += advance
        if index >= len(arguments) or executable_name(arguments[index]) not in _ERRAND_EXECUTABLES:
            return ()
        return arguments[index + 1 :]

    def _requires_review(self, arguments: tuple[str, ...]) -> bool:
        if not arguments:
            return False
        if _may_expand(arguments[0]):
            return True  # the dispatch itself is unresolved
        if self.operation == "fetch-apply":
            return arguments[0] == "fetch" and self._applies_fetch(arguments[1:])
        return arguments[0] not in self.subcommands and self._executes_job(arguments)

    def _executes_job(self, arguments: tuple[str, ...]) -> bool:
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token == "--":
                return index + 1 < len(arguments)
            if _may_expand(token):
                return True
            option = _go_option(token)
            if option is None:
                return True  # bare operand before the separator
            name, has_value, _value = option
            if name in _HELP_NAMES:
                return False
            if name in self.run_options_with_values:
                if not has_value:
                    if index + 1 >= len(arguments):
                        return False  # Go reports a missing value and exits
                    index += 1
            elif name not in self.run_flags:
                return True  # unknown option cannot prove a job absent
            index += 1
        return False

    def _applies_fetch(self, arguments: tuple[str, ...]) -> bool:
        apply = False
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if _may_expand(token):
                return True
            option = _go_option(token)
            if option is None:
                return apply  # Go stops at the first operand
            name, has_value, value = option
            if name in _HELP_NAMES:
                return False
            if name in self.fetch_options_with_values:
                if not has_value:
                    if index + 1 >= len(arguments):
                        return apply
                    index += 1
            elif name == "apply":
                if not has_value or value in _GO_TRUE:
                    apply = True
                elif value in _GO_FALSE:
                    apply = False
                else:
                    return True  # Go rejects the value; treat as uncertain
            elif name not in self.fetch_flags:
                return True  # unknown option cannot prove an apply absent
            index += 1
        return apply


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
        matcher=ErrandCommandMatcher("run"),
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
        matcher=ErrandCommandMatcher("fetch-apply"),
        default_mode="review",
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
