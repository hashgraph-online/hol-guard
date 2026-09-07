"""Review installed Repro Surgeon project-command execution (CLI 0.2.1)."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule, matcher_index_hints

_OPTIONS_WITH_VALUES = frozenset(
    {"--match", "--forbid", "--exit", "--config", "--out", "--max-evaluations", "--max-seconds"}
)
_BOOLEAN_OPTIONS = frozenset({"--json", "--help", "--version"})


def _cli_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    # CLI 0.2.1 splits its init payload before calling Node's strict parseArgs.
    return arguments[: arguments.index("--")] if "--" in arguments else arguments


def _valid_options(arguments: tuple[str, ...]) -> bool:
    """Gate help/version exemptions on known strict option shapes, without interpreting values."""
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument.startswith("--"):
            option, assignment, _value = argument.partition("=")
            if option in _OPTIONS_WITH_VALUES:
                if not assignment:
                    index += 1
                    if index >= len(arguments) or arguments[index].startswith("-"):
                        return False
            elif option not in _BOOLEAN_OPTIONS or assignment:
                return False
        elif argument.startswith("-") and argument != "-":
            if not all(flag in "hv" for flag in argument[1:]):
                return False
        index += 1
    return True


@dataclass(frozen=True, slots=True)
class _CliMatcher:
    """Adapt existing structural matchers to the CLI payload and strict-help boundary."""

    matcher: CommandMatcher
    require_valid_options: bool = False

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        segments = tuple(replace(segment, arguments=_cli_arguments(segment.arguments)) for segment in command.segments)
        evidence = self.matcher.match(replace(command, segments=segments))
        if not self.require_valid_options:
            return evidence
        return tuple(
            item
            for item in evidence
            if command.confidence == "exact" and _valid_options(segments[item.segment_index].arguments)
        )


def repro_surgeon_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Keep the argv adapter's candidate index as narrow as its wrapped matcher."""
    if not isinstance(matcher, _CliMatcher):
        return None
    hints = matcher_index_hints(matcher.matcher)
    return (hints.executables, hints.keywords) if hints.complete else None


_EXECUTE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            "repro-surgeon",
            subcommand,
            global_options_with_values=_OPTIONS_WITH_VALUES,
            global_flags=frozenset({"--json"}),
            fail_secure_unknown_options=True,
        )
        for subcommand in ("reduce", "resume", "verify", "demo")
    )
)
_ACTION = "Repro Surgeon project-command execution command"
_ALTERNATIVES = (
    "Inspect the selected configuration and source; use doctor for input checks.",
    "Run untrusted project commands in an independently configured container or VM.",
)
_REFERENCES = (
    "https://github.com/pavangupta352/repro-surgeon/blob/v0.2.1/src/cli.ts",
    "https://github.com/pavangupta352/repro-surgeon/blob/v0.2.1/SECURITY.md#execution-boundary",
    "https://github.com/pavangupta352/repro-surgeon/blob/v0.2.1/docs/execution-container.md",
)

REPRO_SURGEON_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.repro-surgeon.execute",
        title="Repro Surgeon project-command execution",
        description=(
            "Reviews reduce, resume, verify, and demo, which execute project commands in temporary copies "
            "with normal host and network permissions. This review is not a sandbox or a source audit."
        ),
        severity="high",
        risk_classes=("execution", "network_egress"),
        action_classes=(_ACTION,),
        safer_alternatives=_ALTERNATIVES,
        matcher=_CliMatcher(_EXECUTE),
        safe_variants=tuple(
            replace(
                variant,
                matcher=_CliMatcher(variant.matcher, require_valid_options=True),
            )
            for variant_id, title, flag in (
                ("help", "Command help", "--help"),
                ("short-help", "Command help", "-h"),
                ("version", "Tool version", "--version"),
                ("short-version", "Tool version", "-v"),
            )
            for variant in (safe_flag_variant(_EXECUTE, variant_id=variant_id, title=title, flag=flag),)
        ),
        example_command="repro-surgeon reduce ./app --out ./app-repro",
    ),
)

REPRO_SURGEON_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.repro-surgeon",
        name="Repro Surgeon command protection",
        description=(
            "Reviews installed Repro Surgeon 0.2.1 execution commands. Doctor, init, and report are outside "
            "this rule; npm/npx launchers remain under Package Firewall. Direct node scripts are not covered."
        ),
        action_classes=(_ACTION,),
        risk_classes=("execution", "network_egress"),
        safer_alternatives=_ALTERNATIVES,
        reference_urls=_REFERENCES,
    ),
)
