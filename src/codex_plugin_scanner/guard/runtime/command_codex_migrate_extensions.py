"""Structured rules and metadata for the Codex Migrate command extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule, _after_leading_options, _segment_matches_executable

# Surface verified against Codex Migrate 1.0.0. Destination-changing authority
# is explicit: export applies component repairs, while serve enables transfer,
# finalization, and verified recovery controls in the local browser. Argparse
# accepts unambiguous long-option prefixes, so each prefix is treated as the
# same flag. Inspect and recovery remain read-only even when --apply is passed;
# inventory and launch do not accept it.
_APPLY_SUBCOMMANDS = ("export", "serve")
_COMMON_OPTIONS_WITH_VALUES = frozenset(
    {
        "--target",
        "--target-home",
        "--source-home",
        "--workspace",
        "--state-dir",
        "--staging-name",
        "--identity-file",
        "--known-hosts-file",
        "--host-key-alias",
    }
)
_COMMON_FLAGS = frozenset({"--no-compress", "--apply", "--help"})
_SUBCOMMAND_OPTION_NAMES = {
    "export": _COMMON_OPTIONS_WITH_VALUES | _COMMON_FLAGS | {"--component", "--json"},
    "serve": _COMMON_OPTIONS_WITH_VALUES | _COMMON_FLAGS | {"--port", "--no-open"},
}


def _unambiguous_long_forms(options: frozenset[str], all_options: frozenset[str]) -> frozenset[str]:
    """Return exact long options and every argparse-accepted unique prefix."""

    return frozenset(
        option[:length]
        for option in options
        for length in range(3, len(option) + 1)
        if sum(candidate.startswith(option[:length]) for candidate in all_options) == 1
    )


_SUBCOMMAND_VALUE_FORMS = {
    subcommand: _unambiguous_long_forms(
        _COMMON_OPTIONS_WITH_VALUES | ({"--component"} if subcommand == "export" else {"--port"}),
        option_names,
    )
    for subcommand, option_names in _SUBCOMMAND_OPTION_NAMES.items()
}
_SUBCOMMAND_HELP_FORMS = {
    subcommand: _unambiguous_long_forms(frozenset({"--help"}), option_names) | {"-h"}
    for subcommand, option_names in _SUBCOMMAND_OPTION_NAMES.items()
}
_APPLY_FLAG_FORMS = tuple(
    sorted(
        set.intersection(
            *(
                set(_unambiguous_long_forms(frozenset({"--apply"}), option_names))
                for option_names in _SUBCOMMAND_OPTION_NAMES.values()
            )
        ),
        key=lambda value: (len(value), value),
    )
)
_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("codex-migrate",),
    ("exec", "codex-migrate"),
    ("xargs", "codex-migrate"),
)
_EXEC_OPTIONS_WITH_VALUES = frozenset({"-a"})
_EXEC_FLAGS = frozenset({"-c", "-l"})
_XARGS_OPTIONS_WITH_VALUES = frozenset(
    {
        "--arg-file",
        "--delimiter",
        "--eof",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--replace",
        "-E",
        "-I",
        "-J",
        "-L",
        "-P",
        "-R",
        "-S",
        "-a",
        "-d",
        "-e",
        "-n",
        "-s",
    }
)
_XARGS_FLAGS = frozenset(
    {
        "--exit",
        "--help",
        "--no-run-if-empty",
        "--null",
        "--open-tty",
        "--show-limits",
        "--verbose",
        "--version",
        "-0",
        "-o",
        "-p",
        "-r",
        "-t",
        "-x",
    }
)


def _wrapper_options(launcher: str) -> tuple[frozenset[str], frozenset[str]]:
    if launcher == "exec":
        return _EXEC_OPTIONS_WITH_VALUES, _EXEC_FLAGS
    if launcher == "xargs":
        return _XARGS_OPTIONS_WITH_VALUES, _XARGS_FLAGS
    return frozenset(), frozenset()


def _apply_matchers() -> tuple[object, ...]:
    return tuple(
        executable_matcher(
            *launcher,
            subcommand,
            required_flags=frozenset({apply_flag}),
            options_with_values=_SUBCOMMAND_VALUE_FORMS[subcommand],
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=_wrapper_options(launcher[0])[0],
            fail_secure_unknown_options=True,
        )
        for launcher in _LAUNCHERS
        for subcommand in _APPLY_SUBCOMMANDS
        for apply_flag in _APPLY_FLAG_FORMS
    )


_CODEX_MIGRATE_APPLY = AnyMatcher(matchers=_apply_matchers())


@dataclass(frozen=True, slots=True)
class CodexMigrateUnresolvedFlagExpansionMatcher:
    """Review expansions that could supply --apply in flag position."""

    launchers: tuple[tuple[str, ...], ...] = _LAUNCHERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                arguments = lowered_arguments
                if launcher[0] in ("exec", "xargs"):
                    value_options, flags = _wrapper_options(launcher[0])
                    arguments = _after_leading_options(arguments, value_options, flags)
                prefix = launcher[1:]
                if arguments[: len(prefix)] != prefix:
                    continue
                arguments = arguments[len(prefix) :]
                if not arguments or arguments[0] not in _APPLY_SUBCOMMANDS:
                    continue
                subcommand = arguments[0]
                remaining = arguments[1:]
                if any(argument in _SUBCOMMAND_HELP_FORMS[subcommand] for argument in remaining):
                    continue
                argument_index = 0
                while argument_index < len(remaining):
                    argument = remaining[argument_index]
                    if argument == "--":
                        break
                    option_name, separator, _value = argument.partition("=")
                    if option_name in _SUBCOMMAND_VALUE_FORMS[subcommand]:
                        argument_index += 1 if separator else 2
                        continue
                    if _is_complete_expansion(remaining, argument_index):
                        evidence.append(
                            MatcherEvidence(
                                segment_index=index,
                                executable=segment.executable,
                                detail="Matched a Codex Migrate flag-position expansion that may enable apply mode.",
                            )
                        )
                        break
                    argument_index += 1
                break
        return tuple(evidence)


def _is_complete_expansion(arguments: tuple[str, ...], index: int) -> bool:
    """Return whether one entire argv token can expand into ``--apply``."""

    argument = arguments[index]
    if argument.startswith("${") and argument.endswith("}"):
        return True
    if argument.startswith("$("):
        return any(candidate.endswith(")") for candidate in arguments[index:])
    if argument.startswith("`"):
        return any(candidate.endswith("`") for candidate in arguments[index:])
    if not argument.startswith("$") or len(argument) < 2:
        return False
    name = argument[1:]
    return name.isidentifier() or name.isdigit() or name in {"@", "*"}


_CODEX_MIGRATE_APPLY_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_CODEX_MIGRATE_APPLY.matchers, CodexMigrateUnresolvedFlagExpansionMatcher()),
)


CODEX_MIGRATE_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.codex-migrate.apply",
        title="Codex Migrate destination-changing operation",
        description=(
            "Identifies Codex Migrate export or serve invocations that explicitly enable --apply, allowing "
            "verified state to be staged, installed, replaced, or recovered on a destination Mac. "
            "Flag-position shell expansions are reviewed because they may resolve to --apply."
        ),
        severity="high",
        risk_classes=("destructive_shell", "execution", "network_egress"),
        action_classes=("Codex Migrate destination-changing operation",),
        safer_alternatives=(
            "Run the same subcommand without --apply and inspect the read-only plan first.",
            "Confirm the destination backup and selected workspace scope before enabling --apply.",
        ),
        matcher=_CODEX_MIGRATE_APPLY_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            *(
                safe_flag_variant(
                    _CODEX_MIGRATE_APPLY,
                    variant_id=f"help-{index}",
                    title="Codex Migrate command help",
                    flag=flag,
                )
                for index, flag in enumerate(sorted(set.union(*map(set, _SUBCOMMAND_HELP_FORMS.values()))))
            ),
        ),
    ),
)


CODEX_MIGRATE_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.codex-migrate",
        name="Codex Migrate command protection",
        description=(
            "Reviews Codex Migrate commands that enable destination-changing migration or recovery operations."
        ),
        action_classes=("Codex Migrate destination-changing operation",),
        risk_classes=("destructive_shell", "execution", "network_egress"),
        safer_alternatives=(
            "Run the command without --apply and inspect the read-only plan first.",
            "Keep the source Mac and an independent backup until the migrated workspace is verified.",
        ),
        reference_urls=(
            "https://github.com/jsegeren/codex-migrate",
            "https://migrate.segeren.com/how-it-works",
        ),
    ),
)
