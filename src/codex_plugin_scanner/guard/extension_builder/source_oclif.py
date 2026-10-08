"""Read oclif's static manifest and preserve the configured topic separator."""

from __future__ import annotations

from .errors import BuilderError
from .io import list_value, object_value
from .models import Operation, make_operation
from .source_cli import merge_grammar, name_hints
from .validation import COMMAND_TOKEN_PATTERN, OPTION_PATTERN, token


def _flag_names(name: str, row: dict[str, object]) -> tuple[str, ...]:
    names = [f"--{token(name)}"]
    char = row.get("char")
    if char is not None:
        names.append(f"-{token(char, maximum=1)}")
    for alias in list_value(row.get("aliases", []), maximum=128):
        value = token(alias)
        names.append(f"{'-' if len(value) == 1 else '--'}{value}")
    for alias in list_value(row.get("charAliases", []), maximum=128):
        names.append(f"-{token(alias, maximum=1)}")
    allow_no = row.get("allowNo", False)
    if not isinstance(allow_no, bool):
        raise BuilderError("oclif_flag", "oclif reversible-flag metadata must be Boolean.")
    if allow_no:
        if row.get("type") != "boolean":
            raise BuilderError("oclif_flag", "Only Boolean oclif flags can declare a no-prefix variant.")
        names.append(f"--no-{name}")
    return tuple(token(option, pattern=OPTION_PATTERN) for option in names)


def _flags(value: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    items = object_value(value)
    if len(items) > 128:
        raise BuilderError("oclif_limit", "oclif flag count exceeds the supported limit.")
    flags: list[str] = []
    values: list[str] = []
    for name, value_row in sorted(items.items()):
        row = object_value(value_row)
        names = _flag_names(name, row)
        if row.get("type") == "boolean":
            flags.extend(names)
        elif row.get("type") == "option":
            if row.get("multiple") is True and row.get("multipleNonGreedy") is not True:
                raise BuilderError(
                    "oclif_option_arity",
                    "Greedy multiple-value oclif options need a manually normalized CLI surface.",
                )
            values.extend(names)
        else:
            raise BuilderError("oclif_flag", "oclif flag type must be explicitly Boolean or option.")
    return merge_grammar(((), ()), tuple(flags), tuple(values))


def _command_path(command_id: object, separator: str) -> tuple[str, ...]:
    if not isinstance(command_id, str):
        raise BuilderError("oclif_command", "oclif command IDs must be strings.")
    path: list[str] = []
    if command_id not in {"", "."}:
        value = token(command_id, pattern=COMMAND_TOKEN_PATTERN, maximum=128)
        parts = value.split(":")
        if any(not part for part in parts):
            raise BuilderError("oclif_command", "oclif command IDs contain an empty topic component.")
        if separator == "space":
            path.extend(token(part) for part in parts)
        else:
            path.append(token(value, pattern=COMMAND_TOKEN_PATTERN))
    return tuple(path)


def oclif_surface(value: object, *, topic_separator: str = "colon") -> tuple[tuple[Operation, ...], tuple[str, ...]]:
    if topic_separator not in {"colon", "space"}:
        raise BuilderError("oclif_separator", "Select colon or space for the oclif topic separator.")
    document = object_value(value)
    commands = object_value(document.get("commands"))
    if len(commands) > 256:
        raise BuilderError("oclif_limit", "oclif manifest exceeds the supported operation limit.")
    operations: list[Operation] = []
    for command_id, value_row in sorted(commands.items()):
        row = object_value(value_row)
        flags, values = _flags(row.get("flags", {}))
        paths = [_command_path(command_id, topic_separator)]
        paths.extend(_command_path(alias, topic_separator) for alias in list_value(row.get("aliases", [])))
        for path in paths:
            if len(operations) >= 256:
                raise BuilderError("oclif_limit", "oclif commands and aliases exceed the supported operation limit.")
            operations.append(
                make_operation(
                    "cli",
                    path=path,
                    flags=flags,
                    options_with_values=values,
                    evidence={"command": row, "path": list(path), "topicSeparator": topic_separator},
                    hints=name_hints(path),
                )
            )
    return tuple(operations), ("manifest-runtime-plugins-not-inspected",)
