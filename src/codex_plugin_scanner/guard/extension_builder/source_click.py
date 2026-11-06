"""Consume Click information exports as data; never import the described CLI."""

from __future__ import annotations

from .errors import BuilderError
from .io import list_value, object_value
from .models import Operation, make_operation
from .source_cli import merge_grammar, name_hints, string_tokens
from .validation import token


def _parameters(value: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    flags: list[str] = []
    values: list[str] = []
    for item in list_value(value, maximum=128):
        row = object_value(item)
        if row.get("param_type_name") == "argument":
            continue
        if row.get("param_type_name") != "option":
            raise BuilderError("click_parameter", "Click export contains an unsupported parameter shape.")
        names = (
            *string_tokens(row.get("opts", []), options=True),
            *string_tokens(row.get("secondary_opts", []), options=True),
        )
        is_flag = row.get("is_flag", False)
        count = row.get("count", False)
        if not isinstance(is_flag, bool) or not isinstance(count, bool):
            raise BuilderError("click_parameter", "Click flag metadata must use Boolean values.")
        if is_flag or count:
            flags.extend(names)
        else:
            if type(row.get("nargs", 1)) is not int or row.get("nargs", 1) != 1:
                raise BuilderError(
                    "click_option_arity",
                    "Multi-value Click options need a manually normalized CLI surface; their arity is not inferred.",
                )
            values.extend(names)
    return merge_grammar(((), ()), tuple(flags), tuple(values))


def click_surface(value: object) -> tuple[tuple[Operation, ...], tuple[str, ...]]:
    document = object_value(value)
    root = object_value(document["command"]) if "command" in document else document
    operations: list[Operation] = []

    def visit(
        row: dict[str, object],
        path: tuple[str, ...],
        inherited: tuple[tuple[str, ...], tuple[str, ...]],
    ) -> None:
        if len(path) > 8 or len(operations) >= 256:
            raise BuilderError("click_limit", "Click command tree exceeds the documented depth or operation limit.")
        if "params" not in row:
            raise BuilderError("click_shape", "Click command exports must declare their parameter inventory.")
        own_flags, own_values = _parameters(row["params"])
        flags, values = merge_grammar(inherited, own_flags, own_values)
        operations.append(
            make_operation(
                "cli",
                path=path,
                flags=flags,
                options_with_values=values,
                evidence={"command": row, "inheritedFlags": list(inherited[0]), "inheritedOptions": list(inherited[1])},
                hints=name_hints(path),
            )
        )
        children = object_value(row.get("commands", {}))
        if len(children) > 256:
            raise BuilderError("click_limit", "Click command tree exceeds the documented operation limit.")
        for name in sorted(children):
            visit(object_value(children[name]), (*path, token(name)), (flags, values))

    visit(root, (), ((), ()))
    return tuple(operations), ("click-runtime-plugins-not-inspected",)
