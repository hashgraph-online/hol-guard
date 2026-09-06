"""Check reviewed literal vectors against the same native grammar used by detectors."""

from __future__ import annotations

from ..runtime.command_matcher_contracts import CommandMatcher
from ..runtime.command_model import parse_shell_command
from ..runtime.command_path_set_matcher import ExecutablePathSetMatcher
from ..runtime.command_rules import ExecutableMatcher
from .errors import BuilderError
from .models import Discovery, Operation


def validate_known_options(operation: Operation, argv: tuple[str, ...]) -> None:
    remaining = argv[len(operation.path) :]
    index = 0
    operands = False
    while index < len(remaining):
        argument = remaining[index]
        if argument == "--" and operation.path:
            operands = True
        elif operands or not argument.startswith("-"):
            if not operation.path:
                raise BuilderError(
                    "safe_variant_scope", "Root safe variants cannot include unknown operations or operands."
                )
        elif argument in operation.flags:
            pass
        else:
            name, separator, _value = argument.partition("=")
            if name not in operation.options_with_values:
                raise BuilderError(
                    "safe_variant_option", "Safe invocations must use explicitly discovered option names and arity."
                )
            if not separator:
                index += 1
                if index >= len(remaining):
                    raise BuilderError(
                        "safe_variant_option", "A reviewed value-taking option is missing its literal value."
                    )
        index += 1


def _matcher(discovery: Discovery, operation: Operation) -> CommandMatcher:
    executables = frozenset({discovery.metadata.executable})
    if not operation.path:
        return ExecutableMatcher(executables=executables)
    return ExecutablePathSetMatcher(
        executables=executables,
        paths=frozenset({operation.path}),
        allow_leading_options=True,
        leading_options_with_values=frozenset(operation.options_with_values),
        interspersed_options_with_values=frozenset(operation.options_with_values),
        interspersed_flags=frozenset(operation.flags),
        fail_secure_unknown_options=True,
    )


def validate_native_bindings(
    discovery: Discovery,
    rows: tuple[tuple[Operation, tuple[str, ...]], ...],
    blocked_ids: frozenset[str],
) -> None:
    if not rows:
        return
    matchers = {operation.operation_id: _matcher(discovery, operation) for operation in discovery.operations}
    for owner, argv in rows:
        validate_known_options(owner, argv)
        command = parse_shell_command(" ".join((discovery.metadata.executable, *argv)))
        matches = [operation for operation in discovery.operations if matchers[operation.operation_id].match(command)]
        if any(operation.operation_id in blocked_ids for operation in matches):
            raise BuilderError(
                "safe_variant_conflict", "A safe invocation overlaps a native explicitly blocked operation."
            )
        longest = max((len(operation.path) for operation in matches), default=-1)
        owners = {operation.operation_id for operation in matches if len(operation.path) == longest}
        if owners != {owner.operation_id}:
            raise BuilderError(
                "safe_variant_scope", "Native parsing assigns this safe invocation to another or ambiguous operation."
            )
