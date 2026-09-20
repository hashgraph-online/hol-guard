"""Structured rules and metadata for the omairc command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_launcher_floors import _XARGS_VALUE_OPTIONS
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import matches_subcommands_conservatively
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
    _after_leading_options,
    _segment_matches_executable,
)

# Flag surface verified against omairc's local CLI (`src/omairccli.cpp` in
# fredimachado/omairc). Dispatch requires the literal subcommand as argv[0];
# `--network` is a per-command option with a following value. `send` treats
# `--help` as help only before the target; after the target it is message
# text. `raise` takes no operands. Read-only inventory (`connections`/`list`,
# `status`, `names`, `read`, `conversations`) is intentionally unmatched so
# those commands stay automatic.
#
# Conservative matching covers:
# - Standard launcher variants: omairc, omairc.exe, omairc.cmd
# - Shell wrappers: exec omairc ..., exec -a <argv0> omairc ..., xargs omairc ...
# - Fail-secure option parsing: unknown options still match send/raise
# - Incomplete `omairc send` without a target still reviews

_OMAIRC_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("omairc",),
    ("exec", "omairc"),
    ("xargs", "omairc"),
)
_OMAIRC_EXECUTABLES = executable_names("omairc")
_EXEC_VALUE_OPTIONS = frozenset({"-a"})
_NETWORK_OPTIONS_WITH_VALUES = frozenset({"--network"})
_WRAPPER_EXECUTABLES = frozenset({"exec", "xargs"})


def _argument_matches_executable(argument: str, executables: frozenset[str]) -> bool:
    basename = argument.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return basename in executables


def _wrapper_leading_options_with_values(wrapper: str) -> frozenset[str]:
    if wrapper == "xargs":
        return _XARGS_VALUE_OPTIONS
    if wrapper == "exec":
        return _EXEC_VALUE_OPTIONS
    return frozenset()


def _arguments_after_omairc_launcher(
    arguments: tuple[str, ...],
    launcher: tuple[str, ...],
) -> tuple[str, ...] | None:
    candidate = arguments
    if launcher[0] in _WRAPPER_EXECUTABLES:
        candidate = _after_leading_options(
            candidate,
            _wrapper_leading_options_with_values(launcher[0]),
            frozenset(),
        )
        if not candidate or not _argument_matches_executable(candidate[0], _OMAIRC_EXECUTABLES):
            return None
        return candidate[1:]
    return candidate


@dataclass(frozen=True, slots=True)
class OmaircWrapperSubcommandMatcher:
    """Match omairc subcommands launched through exec or xargs."""

    wrapper: str
    subcommands: tuple[str, ...]
    options_with_values: frozenset[str] = frozenset()
    fail_secure_unknown_options: bool = True

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        wrapper_executables = executable_names(self.wrapper)
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, wrapper_executables):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            after_wrapper = _after_leading_options(
                lowered_arguments,
                _wrapper_leading_options_with_values(self.wrapper),
                frozenset(),
            )
            if not after_wrapper or not _argument_matches_executable(after_wrapper[0], _OMAIRC_EXECUTABLES):
                continue
            subcommand_arguments = after_wrapper[1:]
            if (
                subcommand_arguments[: len(self.subcommands)] != self.subcommands
                and (
                    not self.fail_secure_unknown_options
                    or not matches_subcommands_conservatively(
                        subcommand_arguments,
                        self.subcommands,
                        options_with_values=self.options_with_values,
                        known_flags=frozenset(),
                    )
                )
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and structured argument constraints.",
                )
            )
        return tuple(evidence)


def _omairc_direct_matcher(*subcommands: str, options_with_values: frozenset[str] = frozenset()) -> ExecutableMatcher:
    return executable_matcher(
        "omairc",
        *subcommands,
        options_with_values=options_with_values,
        fail_secure_unknown_options=True,
    )


def _omairc_matcher(*subcommands: str, options_with_values: frozenset[str] = frozenset()) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            _omairc_direct_matcher(*subcommands, options_with_values=options_with_values),
            *(
                OmaircWrapperSubcommandMatcher(
                    wrapper=wrapper,
                    subcommands=subcommands,
                    options_with_values=options_with_values,
                )
                for wrapper in _WRAPPER_EXECUTABLES
            ),
        )
    )


_OMAIRC_SEND = _omairc_matcher("send", options_with_values=_NETWORK_OPTIONS_WITH_VALUES)
_OMAIRC_RAISE = _omairc_matcher("raise")
_OMAIRC_RAISE_DIRECT = _omairc_direct_matcher("raise")


@dataclass(frozen=True, slots=True)
class OmaircSendHelpMatcher:
    """Match `omairc send --help` only when help is requested before a target.

    `omairc send '#channel' --help` sends the text `--help` and must stay a
    reviewable send. `--help` is help only while the CLI is still parsing
    options, including `omairc send --network <id> --help`.
    """

    subcommand: str = "send"
    launchers: tuple[tuple[str, ...], ...] = _OMAIRC_LAUNCHERS
    network_options: frozenset[str] = _NETWORK_OPTIONS_WITH_VALUES

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, executable_names(launcher[0])):
                    continue
                subcommand_arguments = _arguments_after_omairc_launcher(lowered_arguments, launcher)
                if subcommand_arguments is None or subcommand_arguments[:1] != (self.subcommand,):
                    continue
                if _send_help_requested(subcommand_arguments[1:], self.network_options):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched omairc send command help requested before a target.",
                        )
                    )
                break
        return tuple(evidence)


def _send_help_requested(arguments: tuple[str, ...], network_options: frozenset[str]) -> bool:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return False
        if argument in network_options:
            index += 2
            continue
        option_name, separator, _value = argument.partition("=")
        if option_name in network_options and separator == "=":
            index += 1
            continue
        if argument == "--help":
            return True
        if argument.startswith("-"):
            index += 1
            continue
        return False
    return False


OMAIRC_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "omairc message send command": ("network_egress",),
    "omairc window raise command": ("execution",),
}

OMAIRC_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.omairc.send",
        title="omairc message send",
        description=(
            "Identifies `omairc send`, which delivers a PRIVMSG through a running "
            "Omairc window without changing the selected conversation. Incomplete "
            "send invocations and `--help` after the target stay reviewable because "
            "they cannot prove a message will not be delivered. Uncertain parses of "
            "send still review instead of implying safety."
        ),
        severity="high",
        risk_classes=("network_egress",),
        action_classes=("Omairc message send command",),
        safer_alternatives=(
            "Confirm the network, target, and exact message text before sending.",
            "Use omairc read, names, status, or connections to inspect state first.",
            "Do not retry send when the CLI reports an uncertain result; confirm with read --last.",
        ),
        matcher=_OMAIRC_SEND,
        default_mode="review",
        safe_variants=(
            CommandSafeVariant(
                variant_id="help",
                title="omairc send command help",
                matcher=OmaircSendHelpMatcher(),
            ),
        ),
        example_command="omairc send",
    ),
    CommandSafetyRule(
        rule_id="command.omairc.raise",
        title="omairc window raise",
        description=(
            "Identifies `omairc raise`, which activates the existing Omairc window. "
            "Raise is reviewed because it changes the user's desktop focus."
        ),
        severity="medium",
        risk_classes=("execution",),
        action_classes=("Omairc window raise command",),
        safer_alternatives=("Do not raise the window unless the user asked to bring Omairc to the front.",),
        matcher=_OMAIRC_RAISE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                AnyMatcher(matchers=(_OMAIRC_RAISE_DIRECT,)),
                variant_id="help",
                title="omairc raise command help",
                flag="--help",
            ),
        ),
        example_command="omairc raise",
    ),
)

OMAIRC_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.omairc",
        name="omairc command protection",
        description=(
            "Reviews omairc commands that send IRC messages or raise the running "
            "window. Read-only inventory commands stay automatic."
        ),
        action_classes=(
            "Omairc message send command",
            "Omairc window raise command",
        ),
        risk_classes=("network_egress", "execution"),
        safer_alternatives=(
            "Confirm the network, target, and exact message text before sending.",
            "Use omairc read, names, status, or connections to inspect state first.",
        ),
        reference_urls=("https://github.com/fredimachado/omairc",),
        executables=("omairc",),
        ecosystem_ids=("omairc",),
    ),
)
