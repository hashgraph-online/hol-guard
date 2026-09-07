"""Parse explicit CLI surfaces and conventional help text without executing them."""

from __future__ import annotations

import re

from .errors import BuilderError
from .io import list_value, object_value, text_from_bytes
from .models import Operation, make_operation
from .validation import COMMAND_TOKEN_PATTERN, OPTION_PATTERN, TOKEN_PATTERN, token

_READ_NAMES = frozenset({"read", "get", "show", "status", "list", "inspect", "describe"})
_DESTRUCTIVE_NAMES = frozenset({"delete", "remove", "rm", "destroy", "drop", "prune", "reset", "truncate", "purge"})
_SGR = re.compile(r"\x1b\[[0-9;]*m")
_COMMAND_ROW = re.compile(r"^\s{2,}([A-Za-z0-9][A-Za-z0-9_.+-]{0,63})(?:\s{2,}|(?:\s*$))")
_OPTION = re.compile(r"(?<![A-Za-z0-9_-])--?[A-Za-z0-9][A-Za-z0-9_-]*")
_HEADINGS = frozenset({"commands:", "available commands:", "subcommands:"})


def name_hints(parts: tuple[str, ...]) -> tuple[str, ...]:
    words = {word for part in parts for word in re.split(r"[_.:+-]", part.lower())}
    result: list[str] = []
    if words & _READ_NAMES:
        result.append("read-name")
    if words & _DESTRUCTIVE_NAMES:
        result.append("destructive-name")
    return tuple(result)


def string_tokens(value: object, *, options: bool = False) -> tuple[str, ...]:
    result = tuple(
        token(item, pattern=OPTION_PATTERN if options else TOKEN_PATTERN) for item in list_value(value, maximum=128)
    )
    if len(result) != len(set(result)):
        raise BuilderError("duplicate_token", "An option list contains duplicate entries.")
    return result


def merge_grammar(
    inherited: tuple[tuple[str, ...], tuple[str, ...]],
    flags: tuple[str, ...],
    values: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    all_flags = set(inherited[0]) | set(flags)
    all_values = set(inherited[1]) | set(values)
    if all_flags & all_values or len(all_flags) + len(all_values) > 128:
        raise BuilderError("option_arity", "Option grammar is ambiguous or exceeds the supported option limit.")
    return tuple(sorted(all_flags)), tuple(sorted(all_values))


def cli_surface(value: object) -> tuple[tuple[Operation, ...], tuple[str, ...]]:
    document = object_value(value)
    if document.get("schemaVersion") != "guard.cli-surface.v1" or set(document) - {
        "schemaVersion",
        "commands",
        "flags",
        "optionsWithValues",
    }:
        raise BuilderError("cli_surface", "Expected a supported guard.cli-surface.v1 document.")
    inherited = merge_grammar(
        ((), ()),
        string_tokens(document.get("flags", []), options=True),
        string_tokens(document.get("optionsWithValues", []), options=True),
    )
    operations: list[Operation] = []
    for item in list_value(document.get("commands")):
        row = object_value(item)
        if set(row) - {"path", "flags", "optionsWithValues", "description"}:
            raise BuilderError("cli_surface", "CLI operation contains unsupported fields.")
        if "description" in row and not isinstance(row["description"], str):
            raise BuilderError("cli_surface", "CLI descriptions must be strings.")
        path = tuple(token(part, pattern=COMMAND_TOKEN_PATTERN) for part in list_value(row.get("path"), maximum=8))
        flags, values = merge_grammar(
            inherited,
            string_tokens(row.get("flags", []), options=True),
            string_tokens(row.get("optionsWithValues", []), options=True),
        )
        operations.append(
            make_operation(
                "cli",
                path=path,
                flags=flags,
                options_with_values=values,
                evidence={"row": row, "globalGrammar": [list(inherited[0]), list(inherited[1])]},
                hints=name_hints(path),
            )
        )
    return tuple(operations), ()


def _help_options(lines: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    flags: set[str] = set()
    values: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("-"):
            continue
        column = re.split(r"\s{2,}", stripped, maxsplit=1)[0]
        matches = list(_OPTION.finditer(column))
        if not matches:
            continue
        suffix = column[matches[-1].end() :].strip(" ,")
        names = {match.group(0) for match in matches}
        if suffix and not suffix.startswith("[no-"):
            values.update(names)
        else:
            flags.update(names)
    return merge_grammar(((), ()), tuple(flags), tuple(values))


def help_surface(content: bytes) -> tuple[tuple[Operation, ...], tuple[str, ...]]:
    cleaned = _SGR.sub("", text_from_bytes(content))
    if any((ord(char) < 32 and char not in "\n\r\t") or 127 <= ord(char) <= 159 for char in cleaned):
        raise BuilderError("help_control", "Help export contains unsupported terminal control sequences.")
    lines = cleaned.splitlines()
    if len(lines) > 10_000:
        raise BuilderError("help_limit", "Help export exceeds the supported line budget.")
    paths: list[tuple[str, ...]] = [()]
    active = False
    for line in lines:
        if line.strip().lower() in _HEADINGS:
            active = True
            continue
        if line and not line[0].isspace():
            active = False
        if active:
            match = _COMMAND_ROW.match(line)
            if match:
                if len(paths) >= 256:
                    raise BuilderError("help_limit", "Help command inventory exceeds the operation limit.")
                paths.append((token(match.group(1)),))
    flags, values = _help_options(lines)
    operations = tuple(
        make_operation(
            "cli",
            path=path,
            flags=flags,
            options_with_values=values,
            evidence={"path": list(path), "flags": list(flags), "optionsWithValues": list(values)},
            hints=name_hints(path),
        )
        for path in paths
    )
    limitations = ("help-inventory-partial",)
    if len(paths) == 1:
        limitations += ("unrecognized-help-grammar",)
    return operations, limitations
