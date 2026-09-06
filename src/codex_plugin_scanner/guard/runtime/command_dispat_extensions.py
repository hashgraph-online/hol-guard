"""Structured release-start protection for Dispat's default and release commands."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_names
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import known_option_advance
from .command_rules import CommandSafetyRule, _segment_matches_executable

# Dispat uses interspersed pflag options. These are the value-taking options
# accepted by release (including global options and the background update check).
# Consume their values before looking for the command word: a package or root
# named "status" must never turn a release into a preview.
_VALUE_OPTIONS = frozenset(
    {
        "--root",
        "--config",
        "--env-file",
        "--concurrency",
        "--log-level",
        "--log-format",
        "--package",
        "-p",
        "--space",
        "-s",
        "--group",
        "-g",
        "--owner",
        "--repo",
        "--api-url",
        "--token-env",
    }
)
_BOOL_OPTIONS = frozenset({"--quiet-parser", "--strict", "--require-release", "--help", "-h", "--version"})
_TRUE_VALUES = frozenset({"1", "t", "T", "TRUE", "true", "True"})
_FALSE_VALUES = frozenset({"0", "f", "F", "FALSE", "false", "False"})


def _release_intent(arguments: tuple[str, ...]) -> str | None:
    """Classify canonical argv without reading config or reparsing shell text.

    Unknown/malformed options retain review evidence rather than creating a
    preview exemption. Only a positively identified help/version invocation
    exits quietly; pflag boolean assignments are case-sensitive and last-wins.
    """
    operands: list[str] = []
    exits = {"--help": False, "--version": False}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            if index + 1 < len(arguments):
                return "Uncertain release invocation: release does not forward arguments."
            break
        if not argument.startswith("-") or argument == "-":
            if not operands and argument != "release":
                return None  # Other commands and run-script shorthands are outside this rule.
            operands.append(argument)
            index += 1
            continue
        # Normalize the help shorthand only, preserving option values verbatim.
        if argument == "-h" or argument.startswith("-h="):
            argument = "--help" + argument[2:]
        name, separator, value = argument.partition("=")
        if name in _BOOL_OPTIONS:
            if separator and value not in _TRUE_VALUES | _FALSE_VALUES:
                return "Uncertain release invocation: unsupported boolean value."
            if name in exits:
                exits[name] = not separator or value in _TRUE_VALUES
        advance = known_option_advance(argument, options_with_values=_VALUE_OPTIONS, known_flags=_BOOL_OPTIONS)
        if advance is None or index + advance > len(arguments):
            return "Uncertain release invocation: unknown option or missing value."
        if argument.startswith("-") and not argument.startswith("--"):
            # In a short cluster, h is help only before a value-taking option:
            # -hpapi asks for help; -phelp selects the package named "help".
            for character in argument[1:]:
                if f"-{character}" in _VALUE_OPTIONS:
                    break
                if character == "h":
                    exits["--help"] = True
        index += advance
    if any(exits.values()):
        return None
    if len(operands) > 1:
        return "Uncertain release invocation: unexpected positional arguments."
    return "Matched Dispat's default or explicit release start."


@dataclass(frozen=True, slots=True)
class DispatReleaseMatcher:
    """Match release starts, with executable-only registry indexing."""

    executables: frozenset[str] = executable_names("dispat")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None or not _segment_matches_executable(segment, self.executables):
                continue
            detail = (
                "Uncertain release invocation: shell parsing is incomplete."
                if command.confidence != "exact"
                else _release_intent(segment.arguments)
            )
            if detail is not None:
                evidence.append(
                    MatcherEvidence(
                        segment_index=index,
                        executable=segment.executable.replace("\\", "/").rsplit("/", 1)[-1],
                        detail=detail,
                    )
                )
        return tuple(evidence)


DISPAT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.dispat.release",
        title="Dispat release start",
        description=(
            "Identifies default and explicit Dispat release runs, which execute configured version, build and "
            "publish stages and may create commits, push tags and publish GitHub releases."
        ),
        severity="high",
        risk_classes=("execution", "network_egress"),
        action_classes=("Dispat release command",),
        safer_alternatives=("Run dispat status with the same selection flags and review the plan before releasing.",),
        matcher=DispatReleaseMatcher(),
        example_command="dispat release",
    ),
)

DISPAT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.dispat",
        name="Dispat release protection",
        description="Reviews Dispat release starts while leaving status previews quiet.",
        action_classes=("Dispat release command",),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=("Run dispat status with the same selection flags before releasing.",),
        reference_urls=("https://github.com/yohimik/dispat", "https://dispat.dev/"),
        executables=("dispat", "dispat.exe", "dispat.cmd"),
        ecosystem_ids=("dispat",),
    ),
)
