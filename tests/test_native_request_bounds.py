"""No bridge offers the resident a request its own transport will refuse."""

from __future__ import annotations

import ast
import functools
from dataclasses import dataclass, field
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
_PACKAGE = "codex_plugin_scanner"
_GUARD = _SRC / _PACKAGE / "guard"
# The client measures the bytes it is about to frame and the resident measures
# the frame it received, so this one name is the ceiling every other bound
# answers to.
_CEILING_MODULE = _GUARD / "native_resident_client.py"
_CEILING_NAME = "_MAX_REQUEST_BYTES"
# The keyword a bridge hands its bound to. Scanning for the keyword rather than
# for a list of constant names is what keeps this honest: a bridge that spells
# its bound ``_MAX_WIRE_BYTES``, writes the arithmetic inline, or adds a
# envelope's slack to its op's number is still passing a request bound, and a
# name list would have quietly stopped looking at it.
_BOUND_KEYWORD = "max_request_bytes"
# The one expression this scan cannot resolve: a helper that takes the bound as
# a parameter and forwards it. Its default is read from the signature instead,
# and every caller that overrides it is a call site of its own.
_FORWARDED = ("max_request_bytes",)


@dataclass(frozen=True)
class _Facts:
    """What one module says about names, read without importing it."""

    constants: dict[str, ast.expr] = field(default_factory=dict)
    # A local name bound to another module's attribute, or to the module itself.
    bindings: dict[str, tuple[Path, str | None]] = field(default_factory=dict)


@dataclass(frozen=True)
class _Site:
    """One place a request bound is handed to the transport."""

    module: str
    line: int
    source: str
    value: int | None


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_module(path: Path, node: ast.ImportFrom) -> Path | None:
    """The directory or file ``from ... import`` names, if it is ours."""

    if node.level:
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
        parts = node.module.split(".") if node.module else []
    elif node.module and node.module.split(".")[0] == _PACKAGE:
        base = _SRC
        parts = node.module.split(".")
    else:
        return None
    target = base.joinpath(*parts)
    if target.with_suffix(".py").is_file():
        return target.with_suffix(".py")
    return target if target.is_dir() else None


@functools.cache
def _facts(path: Path) -> _Facts:
    facts = _Facts()
    for node in _parse(path).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                facts.constants[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            # ``_MAX_REQUEST_BYTES: Final = 6 * 1024 * 1024`` declares a bound too.
            facts.constants[node.target.id] = node.value
        elif isinstance(node, ast.ImportFrom):
            module = _imported_module(path, node)
            if module is None:
                continue
            for alias in node.names:
                local = alias.asname or alias.name
                if module.is_dir():
                    submodule = module / f"{alias.name}.py"
                    if submodule.is_file():
                        facts.bindings[local] = (submodule, None)
                    continue
                facts.bindings[local] = (module, alias.name)
    return facts


def _name_value(name: str, path: Path, depth: int = 0) -> int | None:
    """The integer a name stands for, followed across our own imports."""

    if depth > 12:
        return None
    facts = _facts(path)
    declared = facts.constants.get(name)
    if declared is not None:
        return _literal_int(declared, path, depth + 1)
    bound = facts.bindings.get(name)
    if bound is None or bound[1] is None:
        return None
    return _name_value(bound[1], bound[0], depth + 1)


def _literal_int(node: ast.expr, path: Path, depth: int = 0) -> int | None:
    """The integer an expression spells out, or ``None`` if it needs running.

    These bounds are written the way the Rust side writes them -- as a count of
    kibibytes, sometimes with a frame's slack taken off or an envelope's slack
    added on -- so the arithmetic is read here rather than the module imported
    for it.
    """

    if depth > 16:
        return None
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, int) else None
    if isinstance(node, ast.Name):
        return _name_value(node.id, path, depth + 1)
    if isinstance(node, ast.Attribute):
        # ``transport._MAX_NATIVE_REQUEST_BYTES``: a module alias, not an object.
        if isinstance(node.value, ast.Name):
            bound = _facts(path).bindings.get(node.value.id)
            if bound is not None and bound[1] is None:
                return _name_value(node.attr, bound[0], depth + 1)
        return None
    if not isinstance(node, ast.BinOp):
        return None
    left = _literal_int(node.left, path, depth + 1)
    right = _literal_int(node.right, path, depth + 1)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Mult):
        return left * right
    if isinstance(node.op, ast.Add):
        return left + right
    if isinstance(node.op, ast.Sub):
        return left - right
    return None


def _is_none(node: ast.expr) -> bool:
    """A bound defaulting to ``None`` is a bound the caller has yet to choose."""

    return isinstance(node, ast.Constant) and node.value is None


def _bound_expressions(path: Path) -> list[tuple[int, ast.expr]]:
    """Every expression this module offers the transport as a request bound."""

    found: list[tuple[int, ast.expr]] = []
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Call):
            found.extend(
                (keyword.value.lineno, keyword.value) for keyword in node.keywords if keyword.arg == _BOUND_KEYWORD
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            names = [argument.arg for argument in arguments.kwonlyargs]
            found.extend(
                (default.lineno, default)
                for name, default in zip(names, arguments.kw_defaults, strict=True)
                if name == _BOUND_KEYWORD and default is not None and not _is_none(default)
            )
    return found


def _sites() -> list[_Site]:
    sites: list[_Site] = []
    for path in sorted(_GUARD.rglob("*.py")):
        for line, node in _bound_expressions(path):
            sites.append(
                _Site(
                    module=str(path.relative_to(_GUARD)),
                    line=line,
                    source=ast.unparse(node),
                    value=_literal_int(node, path),
                )
            )
    return sites


def _ceiling() -> int:
    bound = _name_value(_CEILING_NAME, _CEILING_MODULE)
    assert bound is not None, f"{_CEILING_MODULE.name} no longer declares {_CEILING_NAME}"
    return bound


_SITES = _sites()
_RESOLVED = [site for site in _SITES if site.value is not None]


def test_the_transport_ceiling_is_readable() -> None:
    """The scan is worth nothing if it cannot find what it compares against."""

    assert _ceiling() > 0
    # A scan that stopped matching would pass every assertion below by finding
    # nothing, so the count it found is itself part of the contract.
    assert len(_RESOLVED) > 50


def test_every_bound_offered_to_the_transport_is_readable() -> None:
    """A bound this scan cannot read is a bound nothing is checking.

    One helper takes its bound as a parameter so its callers can lower it. Its
    own default is read from the signature and each caller is a site in its own
    right, so the forwarded name is the only expression allowed to be opaque.
    """

    opaque = {site.source for site in _SITES if site.value is None}
    assert opaque <= set(_FORWARDED), f"unreadable request bounds: {sorted(opaque - set(_FORWARDED))}"


@pytest.mark.parametrize(("site"), _RESOLVED, ids=lambda site: f"{site.module}:{site.line}")
def test_a_bridge_never_offers_more_than_one_frame(site: _Site) -> None:
    """A bound above the ceiling is one no request can ever reach.

    The client refuses anything larger before it frames it, and the resident
    refuses the frame itself, so a request between the two bounds comes back as
    a broken runtime rather than as a request that asked for too much.

    Equality with the ceiling is allowed, and is what a bridge that mirrors the
    transport should say. The bridge's bound and the client's own check both
    measure the same serialized envelope -- the bridge hands that exact byte
    string on -- so a bound equal to the ceiling admits every request the client
    would have framed and no more. The slack a bridge takes off instead is for
    the gap between an envelope and the canonical request inside it, which is a
    question for the op's bound on the Rust side, not for this one.
    """

    assert site.value is not None
    assert site.value <= _ceiling(), f"{site.module}:{site.line} offers {site.source} above what the transport carries"
