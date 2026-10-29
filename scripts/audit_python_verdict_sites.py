"""Find every Python site that produces a Guard verdict from Python control flow.

MAJ-AC-01 asks whether any entry root still authorizes an operation on a verdict
Python computed. Reachability and line counts cannot answer that, so this walks
the package's syntax tree instead and reports each function that turns Python
control flow into one of the enforced ``GuardAction`` strings.

It reports three shapes:

``return "allow"``
    a function whose own branching settles on a verdict;
``decision = "allow"``
    an assignment to a name, attribute or constant-keyed subscript the runtime
    reads as the enforced verdict;
``f(policy_action="allow")``
    a call that passes one as the verdict argument.

A verdict literal reached through a conditional expression or a boolean operator
counts in all three, so ``decision = "allow" if allowed else "block"`` is a site
that produces both actions. The scanner deliberately does no data-flow analysis:
a verdict that reaches a bare ``return`` through a local name is seen only where
that name was assigned, which is why the assignment shape matches on the
verdict-named targets rather than on the returned expression. Anything subtler
than that -- a verdict built by string arithmetic, read out of a table, or
carried through a helper -- is outside what a syntax scan can settle, and the
audit document says so rather than claiming otherwise.

Finding a site is not itself a defect. Decoding a signed remote answer, filing
the user's approval-gate pick, rendering the resident's reply and failing closed
when the resident cannot be reached all land here, and all of them are allowed.
What the invariant forbids is Python *composing* a verdict the resident did not
give. Each known site therefore carries its audited reading in
``docs/guard/audits/python-verdict-sites.json``; this script compares what it
finds against that baseline so a new site has to be audited before it lands.

Run it from the repository root::

    python3 scripts/audit_python_verdict_sites.py            # list what is there
    python3 scripts/audit_python_verdict_sites.py --check    # fail on drift
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from types import MappingProxyType

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "src" / "codex_plugin_scanner"
BASELINE = REPO_ROOT / "docs" / "guard" / "audits" / "python-verdict-sites.json"

# ``GuardAction`` in src/codex_plugin_scanner/guard/models.py.
ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
# Names the runtime reads as the enforced verdict, rather than as a label, a
# display bucket or a test fixture.
VERDICT_NAMES = frozenset(
    {
        "action",
        "action_floor",
        "decision",
        "effect",
        "floor",
        "guard_action",
        "policy_action",
        "policy_decision",
        "resolved_action",
        "verdict",
    }
)


Constants = Mapping[str, frozenset[str]]
_NO_CONSTANTS: Constants = MappingProxyType({})


def _actions(node: ast.expr | None, constants: Constants = _NO_CONSTANTS) -> set[str]:
    """Every ``GuardAction`` string this expression can evaluate to."""

    if isinstance(node, ast.Constant):
        return {node.value} if isinstance(node.value, str) and node.value in ACTIONS else set()
    if isinstance(node, ast.Name):
        # A module-level verdict constant, resolved so ``return _ALLOW`` is not
        # invisible merely because the literal sits a few lines up.
        return set(constants.get(node.id, ()))
    if isinstance(node, ast.IfExp):
        return _actions(node.body, constants) | _actions(node.orelse, constants)
    if isinstance(node, ast.BoolOp):
        return set().union(*(_actions(value, constants) for value in node.values))
    if isinstance(node, (ast.Tuple, ast.List)) and node.elts:
        # ``return "allow", reason`` is how the hook adapters hand a verdict
        # back alongside its text.
        return set().union(*(_actions(element, constants) for element in node.elts))
    if isinstance(node, ast.Dict):
        # ``{**_ALLOW}`` and a verdict-keyed literal both carry one.
        found: set[str] = set()
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None or (isinstance(key, ast.Constant) and key.value in VERDICT_NAMES):
                found |= _actions(value, constants)
        return found
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        # ``dict(_ALLOW)`` is how the daemon hands back a copy of one.
        return set().union(
            *(_actions(argument, constants) for argument in node.args),
            *(_actions(keyword.value, constants) for keyword in node.keywords),
            set(),
        )
    return set()


def _verdict_constants(tree: ast.Module) -> dict[str, frozenset[str]]:
    """Module-level names bound to a verdict, or to a payload carrying one."""

    constants: dict[str, frozenset[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        found = _actions(value, constants)
        if not found:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                constants[target.id] = frozenset(found)
    return constants


def _target_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        # ``updated["policy_action"] = ...`` reaches the runtime the same way a
        # named assignment does.
        value = target.slice.value
        return value if isinstance(value, str) else None
    return None


def _own_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """The function's own nodes, without descending into a nested scope.

    ``ast.walk`` queues a node's children before it yields the node, so
    skipping a nested ``FunctionDef`` when it comes up still visits its body and
    charges its verdicts to the enclosing function. This refuses to enter the
    nested scope in the first place; a nested function is reported under its own
    name by :func:`discover`.
    """

    stack: list[ast.AST] = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _hits(
    func: ast.FunctionDef | ast.AsyncFunctionDef, constants: Constants = _NO_CONSTANTS
) -> list[dict[str, object]]:
    """Every verdict this function's body produces from its own control flow."""

    found: list[dict[str, object]] = []
    for node in _own_nodes(func):
        if isinstance(node, ast.Return):
            for action in _actions(node.value, constants):
                found.append({"line": node.lineno, "kind": "return", "value": action})
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(_target_name(target) in VERDICT_NAMES for target in targets):
                for action in _actions(node.value, constants):
                    found.append({"line": node.lineno, "kind": "assign", "value": action})
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if not (isinstance(key, ast.Constant) and key.value in VERDICT_NAMES):
                    continue
                for action in _actions(value, constants):
                    found.append(
                        {
                            "line": node.lineno,
                            "kind": f"dict:{key.value}",
                            "value": action,
                        }
                    )
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg not in VERDICT_NAMES:
                    continue
                for action in _actions(keyword.value, constants):
                    found.append(
                        {
                            "line": node.lineno,
                            "kind": f"keyword:{keyword.arg}",
                            "value": action,
                        }
                    )
    return sorted(found, key=lambda hit: (hit["line"], hit["kind"], hit["value"]))


def _function_sites(tree: ast.Module, file: str, prefix: str = "") -> Iterator[dict[str, object]]:
    constants = _verdict_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        hits = _hits(node, constants)
        if hits:
            yield {
                "file": file,
                "func": f"{prefix}{node.name}",
                "line": node.lineno,
                "hits": hits,
            }


def _literal_labels(tree: ast.Module) -> dict[int, str]:
    """The assigned name each string literal in this module belongs to."""

    labels: dict[int, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if not names:
            continue
        for value in ast.walk(node.value):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                labels.setdefault(id(value), names[0])
    return labels


def _embedded_sources(tree: ast.Module) -> Iterator[tuple[str, int, str]]:
    """Each string literal in this module that is itself Python source.

    The bounded CLI hook client and the Cursor hook script are not imported;
    they are written out as a script and run by the harness on the hook path.
    Their text lives in this package as string constants, so a scan that only
    reads module-level code would miss the Python that actually renders a
    harness's verdict. Yields the literal's label, its line in the enclosing
    module, and its source.
    """

    labels = _literal_labels(tree)
    unnamed = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        text = node.value
        if not (text.startswith("def ") or "\ndef " in text):
            continue
        label = labels.get(id(node))
        if label is None:
            # A literal with no name of its own is counted rather than placed.
            # Its line number would do neither job: an edit anywhere above it
            # moves it, and before Python 3.12 the constant parts of an
            # f-string carry the enclosing JoinedStr's position, so the same
            # unchanged file labels it differently on 3.10 and 3.12.
            label = f"literal#{unnamed}"
            unnamed += 1
        yield label, node.lineno, text


def discover(package: Path = PACKAGE) -> list[dict[str, object]]:
    """Every verdict-producing function in the package, in a stable order.

    Covers the package's own modules and the Python it carries as embedded
    script templates. A template that is a format string rather than source --
    Cline's, which interpolates ``{event_name!r}`` and escapes its braces --
    cannot be parsed in place; :func:`unparsed_templates` reports those
    separately so the gate stays honest about what it could not read.
    """

    sites: list[dict[str, object]] = []
    for path in sorted(package.rglob("*.py")):
        file = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        sites.extend(_function_sites(tree, file))
        for label, _line, source in _embedded_sources(tree):
            try:
                embedded = ast.parse(source)
            except SyntaxError:
                continue
            sites.extend(_function_sites(embedded, file, prefix=f"{label}:"))
    return sorted(sites, key=lambda site: (site["file"], site["func"]))


def unparsed_templates(package: Path = PACKAGE) -> list[dict[str, object]]:
    """Embedded script templates this scan could not read as Python."""

    found: list[dict[str, object]] = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for label, line, source in _embedded_sources(tree):
            try:
                ast.parse(source)
            except SyntaxError as error:
                found.append(
                    {
                        "file": path.relative_to(REPO_ROOT).as_posix(),
                        "label": label,
                        "line": line,
                        "reason": error.msg,
                    }
                )
    return sorted(found, key=lambda item: (item["file"], item["label"]))


def site_actions(sites: Iterable[Mapping[str, object]]) -> dict[tuple[str, str], frozenset[str]]:
    """Each site keyed by file and function, mapped to the actions it produces.

    The key alone is not enough to compare against. Nineteen of the audited
    sites were cleared as a class because they can produce nothing more
    permissive than a block or a review; if one of them later grows a
    ``return "allow"`` its key does not change, and that is exactly the
    authority change this guard exists to catch. So the comparison carries the
    action set too, read from the baseline's recorded ``actions`` or, for a
    freshly discovered site, from its own hits.
    """

    actions: dict[tuple[str, str], set[str]] = {}
    for site in sites:
        key = (str(site["file"]), str(site["func"]))
        recorded = site.get("actions")
        if recorded is None:
            hits = site.get("hits") or []
            recorded = [hit["value"] for hit in hits]  # type: ignore[index]
        actions.setdefault(key, set()).update(str(value) for value in recorded)
    return {key: frozenset(value) for key, value in actions.items()}


def _baseline() -> Mapping[str, object]:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _template_keys(templates: Iterable[Mapping[str, object]]) -> set[tuple[str, str]]:
    return {(str(item["file"]), str(item["label"])) for item in templates}


def _check() -> int:
    audit = _baseline()
    found = site_actions(discover())
    audited = site_actions(audit["sites"])  # type: ignore[arg-type]
    added = sorted(set(found) - set(audited))
    removed = sorted(set(audited) - set(found))
    changed = sorted(key for key in set(found) & set(audited) if found[key] != audited[key])
    for file, func in added:
        print(
            f"{file}: {func} produces a Guard verdict and is not in the authority audit.\n"
            f"  Read docs/guard/audits/maj-ac-01-per-root-authority-audit.md, decide whether it\n"
            f"  renders the resident's verdict or composes one, then record it in {BASELINE.name}.",
            file=sys.stderr,
        )
    for file, func in removed:
        print(
            f"{file}: {func} is in the authority audit but no longer produces a verdict. "
            f"Drop its row from {BASELINE.name}.",
            file=sys.stderr,
        )
    for key in changed:
        file, func = key
        was = ", ".join(sorted(audited[key])) or "nothing"
        now = ", ".join(sorted(found[key])) or "nothing"
        print(
            f"{file}: {func} was audited as producing {was} and now produces {now}.\n"
            f"  Re-read it against docs/guard/audits/maj-ac-01-per-root-authority-audit.md\n"
            f"  before updating its row in {BASELINE.name}.",
            file=sys.stderr,
        )
    unreadable = _template_keys(unparsed_templates())
    recorded = _template_keys(audit["unparsed_templates"])  # type: ignore[arg-type]
    for file, label in sorted(unreadable - recorded):
        print(
            f"{file}: the embedded script template {label} is not readable as Python,\n"
            f"  so this scan cannot see the verdicts it produces. Read it by hand and\n"
            f"  record it under unparsed_templates in {BASELINE.name}.",
            file=sys.stderr,
        )
    for file, label in sorted(recorded - unreadable):
        print(
            f"{file}: the embedded script template {label} is readable now. "
            f"Drop it from unparsed_templates in {BASELINE.name}.",
            file=sys.stderr,
        )
    if added or removed or changed or unreadable != recorded:
        return 1
    print(
        f"authority audit: {len(found)} verdict sites, all audited; {len(recorded)} embedded template(s) read by hand"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the package no longer matches the audited baseline",
    )
    args = parser.parse_args(argv)
    if args.check:
        return _check()
    print(json.dumps(discover(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
