"""Structured rules and metadata for Storage Clearer commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_extension_matchers import executable_matcher
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import AnyMatcher, CommandSafetyRule

_SHELL_INLINE_OR_STDIN_OPTIONS = frozenset({"-c", "--command", "-s"})
_SHELL_OPTIONS_WITH_VALUES = frozenset({"+O", "+o", "-O", "-o", "--init-file", "--rcfile"})


def _shell_script_arguments(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Return a shell script path and arguments after leading interpreter options."""

    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            return arguments[index + 1 :]
        option = argument.split("=", 1)[0]
        value_option = next(
            (
                candidate
                for candidate in _SHELL_OPTIONS_WITH_VALUES
                if argument == candidate
                or argument.startswith(f"{candidate}=")
                or (len(candidate) == 2 and argument.startswith(candidate) and len(argument) > 2)
            ),
            None,
        )
        if value_option is not None:
            has_attached_value = argument != value_option
            index += 1 if has_attached_value else 2
            continue
        short_flags = argument[1:] if argument.startswith("-") and not argument.startswith("--") else ""
        if option in _SHELL_INLINE_OR_STDIN_OPTIONS or "c" in short_flags or "s" in short_flags:
            return ()
        if argument.startswith(("-", "+")):
            index += 1
            continue
        return arguments[index:]
    return ()


@final
@dataclass(frozen=True, slots=True)
class _ShellScriptInvocationMatcher:
    """Match cleanup subcommands passed to a supported shell interpreter."""

    interpreters: frozenset[str]
    script_name: str
    subcommands: frozenset[str]

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            executable = segment.executable
            if executable is None or executable.replace("\\", "/").rsplit("/", 1)[-1].lower() not in self.interpreters:
                continue
            script_arguments = _shell_script_arguments(segment.arguments)
            if len(script_arguments) < 2:
                continue
            script_name = script_arguments[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            subcommand = script_arguments[1].lower()
            if script_name != self.script_name or subcommand not in self.subcommands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=executable,
                    detail="Matched a shell-interpreted Storage Clearer cleanup command.",
                )
            )
        return tuple(evidence)


_STORAGE_CLEARER_CLEANUP = AnyMatcher(
    matchers=(
        executable_matcher("storage-clearer.sh", "run"),
        executable_matcher("storage-clearer.sh", "app-run"),
        _ShellScriptInvocationMatcher(
            interpreters=frozenset({"bash", "sh"}),
            script_name="storage-clearer.sh",
            subcommands=frozenset({"app-run", "run"}),
        ),
    )
)

STORAGE_CLEARER_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.storage-clearer.cleanup",
        title="Storage Clearer cleanup execution",
        description=(
            "Identifies Storage Clearer run and app-run cleanup sessions, which can invoke Docker prune commands, "
            "xcrun simctl deletion, or tmutil snapshot thinning."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("Storage Clearer cleanup command",),
        safer_alternatives=(
            "Run audit and review the generated plan before starting cleanup.",
            "Keep Storage Clearer's approval and target-revalidation gates in place.",
        ),
        matcher=_STORAGE_CLEARER_CLEANUP,
        default_mode="review",
        example_command="./storage-clearer.sh run B",
    ),
)

STORAGE_CLEARER_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.storage-clearer",
        name="Storage Clearer command protection",
        description=(
            "Reviews Storage Clearer's run and app-run cleanup entry points while leaving audit, explain, reason, "
            "and plan read-only."
        ),
        action_classes=("Storage Clearer cleanup command",),
        risk_classes=("destructive_shell",),
        safer_alternatives=("Run audit and review the generated plan before starting cleanup.",),
        reference_urls=("https://github.com/khiemnd777/storage-clearer/blob/main/storage-clearer.sh",),
        executables=("storage-clearer.sh",),
    ),
)
