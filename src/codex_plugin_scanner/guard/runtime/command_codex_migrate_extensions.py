"""Structured rules and metadata for the Codex Migrate command extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
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
        if option[:length] in all_options
        or sum(candidate.startswith(option[:length]) for candidate in all_options) == 1
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
_CODEX_MIGRATE_EXECUTABLES = executable_names("codex-migrate")
_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("codex-migrate",),
    *(("exec", executable) for executable in sorted(_CODEX_MIGRATE_EXECUTABLES)),
    *(("xargs", executable) for executable in sorted(_CODEX_MIGRATE_EXECUTABLES)),
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
        "--process-slot-var",
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
_MAX_BRACE_EXPANSION_DEPTH = 4
_MAX_BRACE_EXPANSION_RESULTS = 64


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
                launcher_executables = _CODEX_MIGRATE_EXECUTABLES if len(launcher) == 1 else frozenset({launcher[0]})
                if not _segment_matches_executable(segment, launcher_executables):
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
                    if _expansion_can_equal_apply(remaining, argument_index):
                        evidence.append(
                            MatcherEvidence(
                                segment_index=index,
                                executable=launcher[0],
                                detail="Matched a Codex Migrate flag-position expansion that may enable apply mode.",
                            )
                        )
                        break
                    argument_index += 1
                break
        return tuple(evidence)


def _expansion_can_equal_apply(arguments: tuple[str, ...], index: int) -> bool:
    """Return whether expansions in one shell word can produce an accepted apply flag."""

    candidate = arguments[index]
    if "$(" in candidate or "`" in candidate:
        candidate = _command_expansion_word(arguments, index)
    brace_candidates = _brace_expansion_candidates(candidate)
    if brace_candidates is None:
        return True
    for brace_candidate in brace_candidates:
        if brace_candidate in _APPLY_FLAG_FORMS:
            return True
        literals = _expansion_literal_fragments(brace_candidate)
        if literals is not None and any(_literal_fragments_can_equal(literals, target) for target in _APPLY_FLAG_FORMS):
            return True
    return False


def _literal_fragments_can_equal(literals: tuple[str, ...], target: str) -> bool:
    """Return whether variable gaps between fixed fragments can produce ``target``."""

    prefix, *middle, suffix = literals
    if not target.startswith(prefix) or not target.endswith(suffix):
        return False
    cursor = len(prefix)
    limit = len(target) - len(suffix)
    for literal in middle:
        position = target.find(literal, cursor, limit + 1)
        if position < 0:
            return False
        cursor = position + len(literal)
    return cursor <= limit


def _command_expansion_word(arguments: tuple[str, ...], index: int) -> str:
    """Reassemble only the shell word split around command-substitution spaces."""

    first = arguments[index]
    starts = [position for marker in ("$(", "`") if (position := first.find(marker)) >= 0]
    if not starts:
        return first
    start = min(starts)
    for end in range(index + 1, len(arguments) + 1):
        candidate = " ".join(arguments[index:end])
        if _expansion_end(candidate, start) is not None:
            return candidate
    return first


def _expansion_literal_fragments(candidate: str) -> tuple[str, ...] | None:
    """Split a shell word into fixed literals around complete expansions."""

    fragments: list[str] = []
    literal: list[str] = []
    index = 0
    while index < len(candidate):
        end = _expansion_end(candidate, index)
        if end is None:
            literal.append(candidate[index])
            index += 1
            continue
        fragments.append("".join(literal))
        literal = []
        index = end
    if not fragments:
        return None
    fragments.append("".join(literal))
    return tuple(fragments)


def _expansion_end(candidate: str, index: int) -> int | None:
    if candidate.startswith("${", index):
        closing = candidate.find("}", index + 2)
        return closing + 1 if closing >= 0 else None
    if candidate.startswith("$(", index):
        frames: list[tuple[str | None, int]] = [(None, 0)]
        cursor = index + 2
        while cursor < len(candidate):
            quote, plain_parentheses = frames[-1]
            character = candidate[cursor]
            if quote == "'":
                if character == "'":
                    frames[-1] = (None, plain_parentheses)
                cursor += 1
                continue
            if quote == '"':
                if character == "\\":
                    cursor += 2
                    continue
                if candidate.startswith("$(", cursor):
                    frames.append((None, 0))
                    cursor += 2
                    continue
                if character == '"':
                    frames[-1] = (None, plain_parentheses)
                cursor += 1
                continue
            if character == "\\":
                cursor += 2
                continue
            if character in {"'", '"'}:
                frames[-1] = (character, plain_parentheses)
                cursor += 1
                continue
            if candidate.startswith("$(", cursor):
                frames.append((None, 0))
                cursor += 2
                continue
            if character == "(":
                frames[-1] = (None, plain_parentheses + 1)
                cursor += 1
                continue
            if character == ")":
                if plain_parentheses:
                    frames[-1] = (None, plain_parentheses - 1)
                else:
                    frames.pop()
                if not frames:
                    return cursor + 1
            cursor += 1
        return None
    if candidate[index] == "`":
        closing = candidate.find("`", index + 1)
        return closing + 1 if closing >= 0 else None
    if candidate[index] != "$" or index + 1 >= len(candidate):
        return None
    cursor = index + 1
    if candidate[cursor].isdigit() or candidate[cursor] in {"@", "*"}:
        return cursor + 1
    if not (candidate[cursor].isalpha() or candidate[cursor] == "_"):
        return None
    cursor += 1
    while cursor < len(candidate) and (candidate[cursor].isalnum() or candidate[cursor] == "_"):
        cursor += 1
    return cursor


def _brace_expansion_candidates(candidate: str) -> tuple[str, ...] | None:
    """Expand bounded comma-list braces without executing shell input."""

    return _expand_braces(candidate, depth=0)


def _expand_braces(candidate: str, *, depth: int) -> tuple[str, ...] | None:
    group = _first_brace_group(candidate)
    if group is None:
        return (candidate,)
    if depth >= _MAX_BRACE_EXPANSION_DEPTH:
        return None
    start, end, alternatives = group
    expanded: list[str] = []
    for alternative in alternatives:
        values = _expand_braces(candidate[:start] + alternative + candidate[end + 1 :], depth=depth + 1)
        if values is None:
            return None
        expanded.extend(values)
        if len(expanded) > _MAX_BRACE_EXPANSION_RESULTS:
            return None
    return tuple(dict.fromkeys(expanded))


def _first_brace_group(candidate: str) -> tuple[int, int, tuple[str, ...]] | None:
    """Return the first balanced brace group containing top-level alternatives."""

    start = 0
    while start < len(candidate):
        if candidate[start] == "\\":
            start += 2
            continue
        if candidate[start] != "{":
            start += 1
            continue
        depth = 1
        cursor = start + 1
        alternative_start = cursor
        alternatives: list[str] = []
        while cursor < len(candidate):
            if candidate[cursor] == "\\":
                cursor += 2
                continue
            if candidate[cursor] == "{":
                depth += 1
            elif candidate[cursor] == "}":
                depth -= 1
                if depth == 0:
                    if alternatives:
                        alternatives.append(candidate[alternative_start:cursor])
                        return start, cursor, tuple(alternatives)
                    sequence = _brace_sequence_alternatives(candidate[alternative_start:cursor])
                    if sequence is not None:
                        return start, cursor, sequence
                    break
            elif candidate[cursor] == "," and depth == 1:
                alternatives.append(candidate[alternative_start:cursor])
                alternative_start = cursor + 1
            cursor += 1
        start = cursor + 1
    return None


def _brace_sequence_alternatives(content: str) -> tuple[str, ...] | None:
    """Return bounded Bash-style character or integer sequence alternatives."""

    parts = content.split("..")
    if len(parts) not in {2, 3} or not parts[0] or not parts[1]:
        return None
    start, end = parts[:2]
    step_text = parts[2] if len(parts) == 3 else None
    if len(start) == len(end) == 1:
        start_value, end_value = ord(start), ord(end)
        render = chr
    elif start.lstrip("-").isdigit() and end.lstrip("-").isdigit():
        start_value, end_value = int(start), int(end)
        render = str
    else:
        return None
    direction = 1 if end_value >= start_value else -1
    step = direction if step_text is None else int(step_text) if step_text.lstrip("-").isdigit() else 0
    if step == 0:
        return None
    step = abs(step) * direction
    stop = end_value + direction
    values: list[str] = []
    for value in range(start_value, stop, step):
        values.append(render(value))
        if len(values) > _MAX_BRACE_EXPANSION_RESULTS:
            break
    if not values:
        return None
    return tuple(values)


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
