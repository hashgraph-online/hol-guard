"""Lexical bindings shared by conservative ownership call resolution."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Protocol, TypeVar

from scripts.ci.rust_io_ownership_cache import cached
from scripts.ci.rust_io_ownership_cache import parsed_module as _parsed_module


class FunctionRecordLike(Protocol):
    """Minimum function-record shape needed by the resolver."""

    path: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


RecordT = TypeVar("RecordT", bound=FunctionRecordLike)


@cached
def _local_binding_names(record: FunctionRecordLike) -> frozenset[str]:
    """Return names bound as local values in a function body.

    A direct call such as ``close()`` may invoke a callable stored in a local
    variable rather than a repository helper. Treating every such name as a
    global helper creates false ambiguities and does not improve reachability.
    """

    names: set[str] = set()
    arguments = record.node.args
    for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
        names.add(argument.arg)
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)

    def collect_target(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect_target(item)

    for node in ast.walk(record.node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                collect_target(target)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            collect_target(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    collect_target(item.optional_vars)
        elif isinstance(node, ast.comprehension):
            collect_target(node.target)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return frozenset(names)


_PYTHON_BUILTINS = frozenset(
    {
        "open",
        "len",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "bytes",
        "repr",
        "print",
        "type",
        "id",
        "hash",
        "iter",
        "next",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "reversed",
        "sum",
        "min",
        "max",
        "abs",
        "round",
        "ord",
        "chr",
        "hex",
        "bin",
        "oct",
        "any",
        "all",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "callable",
        "format",
        "input",
        "vars",
        "dir",
        "locals",
        "globals",
        "super",
        "object",
        "property",
        "staticmethod",
        "classmethod",
        "memoryview",
        "bytearray",
        "frozenset",
        "complex",
        "slice",
        "compile",
        "eval",
        "exec",
        "breakpoint",
        "help",
        "exit",
        "quit",
        "aiter",
        "anext",
    }
)


@cached
def _module_level_names(root: Path, record: FunctionRecordLike) -> frozenset[str]:
    """Return names bound at module top level that could shadow builtins."""

    names: set[str] = set()
    tree = _parsed_module(root / record.path)
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(statement.name)
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            names.add(statement.target.id)
    return frozenset(names)
