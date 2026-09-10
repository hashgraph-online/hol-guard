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
_APPLY_FLAG_FORMS = ("--a", "--ap", "--app", "--appl", "--apply")
_OPTIONS_WITH_VALUES = frozenset(
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
        "--component",
        "--port",
    }
)
_KNOWN_FLAGS = frozenset({"--no-compress", "--apply", "--json", "--no-open", "--help", "-h"})
_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("codex-migrate",),
    ("exec", "codex-migrate"),
    ("xargs", "codex-migrate"),
)
_WRAPPER_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_EXPANSION_MARKERS = frozenset({"$", "`"})


def _apply_matchers() -> tuple[object, ...]:
    return tuple(
        executable_matcher(
            *launcher,
            subcommand,
            required_flags=frozenset({apply_flag}),
            options_with_values=_OPTIONS_WITH_VALUES,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
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
                    arguments = _after_leading_options(arguments, _WRAPPER_OPTIONS_WITH_VALUES, frozenset())
                prefix = launcher[1:]
                if arguments[: len(prefix)] != prefix:
                    continue
                arguments = arguments[len(prefix) :]
                if not arguments or arguments[0] not in _APPLY_SUBCOMMANDS:
                    continue
                remaining = arguments[1:]
                argument_index = 0
                while argument_index < len(remaining):
                    argument = remaining[argument_index]
                    if argument == "--":
                        break
                    option_name, separator, _value = argument.partition("=")
                    if option_name in _OPTIONS_WITH_VALUES:
                        argument_index += 1 if separator else 2
                        continue
                    if any(marker in argument for marker in _EXPANSION_MARKERS):
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
            safe_flag_variant(
                _CODEX_MIGRATE_APPLY,
                variant_id="help",
                title="Codex Migrate command help",
                flag="--help",
            ),
            safe_flag_variant(
                _CODEX_MIGRATE_APPLY,
                variant_id="short-help",
                title="Codex Migrate command help",
                flag="-h",
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
