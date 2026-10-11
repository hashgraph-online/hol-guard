"""Wired-Rust rule for the runtime-majority report.

A Rust file counts toward the numerator only when it is reachable from the
``hol-guard-runtime`` entry point (``main.rs`` -> ``runtime_cli`` -> resident
dispatch).  Compiled-in code that nothing wired references yet is reported
separately as ``unwired`` and is not counted until something wired uses it.

Reachability is a static, file-granular name graph.  A wired file ``G``
reaches a file ``F`` when the code of ``G`` (comments, string contents and
``#[cfg(test)]`` regions blanked, ``mod x;`` declarations ignored) contains

* the module alias or file name of ``F``: an alias declared by a ``mod``
  statement is visible only inside the declaring file and its descendants,
  a file stem is visible crate-wide, and either one is visible in another
  crate only when ``G`` also names that crate; or
* a public item name defined or implemented in ``F`` that ``G`` does not
  define itself and that at most ``MAX_AMBIGUITY`` counted files define.

``include!`` targets are textually part of the including file.  The graph
over-approximates calls (a name match is not proof of a call), so the unwired
set is a conservative floor.  Dead functions inside a wired file are not
detected here; rustc's ``dead_code`` lint covers the binary crate.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.ci.runtime_majority_rust import module_children

MAX_AMBIGUITY = 3
ROOT_FILE_NAMES = frozenset({"lib.rs", "main.rs"})

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MOD_DECL = re.compile(r"(?<![\w:])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_]\w*\s*;")
_PUB_PREFIX = r"pub(?P<vis>\s*\([^)]*\))?\s+(?:(?:async|unsafe|const|extern)\s+)*(?:\"[^\"]*\"\s+)?"
_PUB_TYPE = re.compile(r"\b" + _PUB_PREFIX + r"(?:struct|enum|trait|type|union)\s+(?P<name>[A-Za-z_]\w*)")
_PUB_CONST = re.compile(r"\b" + _PUB_PREFIX + r"(?:const|static)\s+(?P<name>[A-Z][A-Z0-9_]*)\b")
_PUB_FREE_FN = re.compile(r"^" + _PUB_PREFIX + r"fn\s+(?P<name>[A-Za-z_]\w*)", re.MULTILINE)
_LOCAL_ITEM = re.compile(r"\b(?:fn|struct|enum|trait|type|const|static|union|let(?:\s+mut)?)\s+([A-Za-z_]\w*)")
_USE_STATEMENT = re.compile(r"\buse\b[^;]*;")
_CALLED = re.compile(r"\b([A-Za-z_]\w*)\s*!?\s*\(")
_MACRO_RULES = re.compile(r"\bmacro_rules\s*!\s*([A-Za-z_]\w*)")
_IMPL_TARGET = re.compile(r"\bimpl\b(?:\s*<[^{;]*?>)?\s+(?:[^{;]*?\bfor\s+)?&?(?:'\w+\s+)?(?:mut\s+)?([A-Za-z_]\w*)")


@dataclass
class WiringFile:
    """One counted Rust file and the names it defines and references."""

    path: str
    crate: str
    loc: int
    stem: str
    is_root: bool
    is_mod_rs: bool
    defined: set[str] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    impl_targets: set[str] = field(default_factory=set)
    parent_only: set[str] = field(default_factory=set)
    local: set[str] = field(default_factory=set)
    referenced: set[str] = field(default_factory=set)
    called: set[str] = field(default_factory=set)
    alias: str = ""
    parent: str = ""
    included_by: str = ""
    public_mod: bool = False


def visible_code(code: str, flags: bytearray) -> str:
    """Code text with comments, string contents and test regions blanked."""
    return "".join(char if flags[index] or char == "\n" else " " for index, char in enumerate(code))


def _stem(relative: Path) -> tuple[str, bool, bool]:
    if relative.name in ROOT_FILE_NAMES:
        return "", True, False
    if relative.name == "mod.rs":
        return relative.parent.name, False, True
    return relative.stem, False, False


def build_files(
    repo: Path, counts: list[Any], analyze: Callable[[str], tuple[int, int, str, bytearray]]
) -> list[WiringFile]:
    files: dict[str, WiringFile] = {}
    by_resolved: dict[Path, WiringFile] = {}
    parsed: dict[str, tuple[str, str, bytearray]] = {}
    for item in counts:
        resolved = (repo / item.path).resolve()
        parts = Path(item.path).parts
        stem, is_root, is_mod_rs = _stem(Path(*parts[(parts.index("src") + 1 if "src" in parts else 0) :]))
        source = resolved.read_text(encoding="utf-8")
        _, _, code, flags = analyze(source)
        text = _MOD_DECL.sub(" ", visible_code(code, flags))
        entry = WiringFile(item.path, item.crate, item.loc, stem, is_root, is_mod_rs)
        entry.referenced = set(_IDENT.findall(text))
        items = [*_PUB_TYPE.finditer(text), *_PUB_CONST.finditer(text), *_PUB_FREE_FN.finditer(text)]
        entry.defined = {m["name"] for m in items if m.re is not _PUB_FREE_FN} | set(_MACRO_RULES.findall(text))
        entry.functions = {m["name"] for m in items if m.re is _PUB_FREE_FN}
        entry.parent_only = {m["name"] for m in items if "super" in (m["vis"] or "") or "self" in (m["vis"] or "")} - {
            m["name"] for m in items if "super" not in (m["vis"] or "") and "self" not in (m["vis"] or "")
        }
        entry.impl_targets = {name for name in _IMPL_TARGET.findall(text) if name[:1].isupper()}
        entry.local = set(_LOCAL_ITEM.findall(text))
        entry.called = set(_CALLED.findall(text)) | {
            name for statement in _USE_STATEMENT.findall(text) for name in _IDENT.findall(statement)
        }
        files[item.path] = entry
        by_resolved[resolved] = entry
        parsed[item.path] = (source, code, flags)
    for path, (source, code, flags) in parsed.items():
        modules, includes = module_children((repo / path).resolve(), source, code, flags)
        for alias, target in modules:
            if target in by_resolved and not by_resolved[target].parent:
                child = by_resolved[target]
                child.parent, child.alias = path, alias
                text = _MOD_DECL.sub(lambda m: m.group(0), visible_code(parsed[path][1], parsed[path][2]))
                child.public_mod = (
                    re.search(r"\bpub(?:\s*\([^)]*\))?\s+mod\s+" + re.escape(alias) + r"\s*;", text) is not None
                )
        for target in includes:
            if target in by_resolved:
                by_resolved[target].included_by = path
    return list(files.values())


def _crate_ident(name: str) -> str:
    return name.replace("-", "_")


def _publicly_named(
    target: WiringFile,
    name: str,
    current: WiringFile,
    by_path: dict[str, WiringFile],
    crate_roots: dict[str, WiringFile],
) -> bool:
    """Cross-crate use needs the item's top-level module named, or a root re-export of the item."""
    top = target
    while top.parent and not by_path[top.parent].is_root:
        top = by_path[top.parent]
    if top.is_root:
        return True
    root = crate_roots.get(target.crate)
    return (top.alias or top.stem) in current.referenced or (root is not None and name in root.referenced)


def _accessible(target: WiringFile, name: str, current: WiringFile, by_path: dict[str, WiringFile], subtree_of) -> bool:
    """A private ``mod`` hides its items from outside the declaring file unless that file re-exports them."""
    node = target
    while node.parent:
        parent = by_path[node.parent]
        if not node.public_mod and current.path not in subtree_of(parent.path) and name not in parent.referenced:
            return False
        node = parent
    return True


def compute_wired(files: list[WiringFile], crate_deps: dict[str, set[str]], entry_crate: str) -> dict[str, str]:
    """Return ``{wired path: first referrer}``; roots map to the empty string."""
    by_path = {item.path: item for item in files}
    owners: dict[str, list[WiringFile]] = {}
    stems: dict[tuple[str, str], list[WiringFile]] = {}
    aliased: dict[str, list[WiringFile]] = {}
    children: dict[str, list[str]] = {}
    for item in files:
        for name in item.defined | item.functions | item.impl_targets:
            owners.setdefault(name, []).append(item)
        if item.stem and not item.parent:
            stems.setdefault((item.crate, item.stem), []).append(item)
        if item.alias:
            aliased.setdefault(item.alias, []).append(item)
        for owner in (item.parent, item.included_by):
            if owner:
                children.setdefault(owner, []).append(item.path)

    def subtree(path: str) -> set[str]:
        found, stack = set(), [path]
        while stack:
            current = stack.pop()
            if current not in found:
                found.add(current)
                stack.extend(children.get(current, ()))
        return found

    subtrees: dict[str, set[str]] = {}
    crate_roots = {item.crate: item for item in files if item.is_root}
    wired: dict[str, str] = {item.path: "" for item in files if item.crate == entry_crate and item.is_root}
    queue: deque[str] = deque(wired)

    def reach(target: WiringFile, via: str) -> None:
        if target.path not in wired:
            wired[target.path] = via
            queue.append(target.path)

    while queue:
        current = by_path[queue.popleft()]
        for child in children.get(current.path, ()):
            target = by_path[child]
            if target.included_by == current.path or target.impl_targets & current.referenced:
                reach(target, current.path)
        crates = {current.crate} | {
            crate for crate in crate_deps.get(current.crate, set()) if _crate_ident(crate) in current.referenced
        }
        for crate in sorted(crates - {current.crate}):
            if crate in crate_roots:
                reach(crate_roots[crate], current.path)
        for name in current.referenced:
            for target in stems.get((current.crate, name), ()):
                reach(target, current.path)
            for crate in crates - {current.crate}:
                for target in stems.get((crate, name), ()):
                    reach(target, current.path)
            for target in aliased.get(name, ()):
                if target.crate == current.crate:
                    scope = subtrees.setdefault(target.parent, subtree(target.parent))
                    if current.path in scope:
                        reach(target, current.path)
                elif target.crate in crates and by_path[target.parent].is_root:
                    reach(target, current.path)
        for name in current.referenced - current.local - current.defined:
            targets = owners.get(name, ())
            if 0 < len(targets) <= MAX_AMBIGUITY:
                for target in targets:
                    if name in target.functions and name not in target.defined and name not in current.called:
                        continue
                    if name in target.parent_only and (
                        not target.parent
                        or current.path not in subtrees.setdefault(target.parent, subtree(target.parent))
                    ):
                        continue
                    if target.crate == current.crate and not _accessible(
                        target, name, current, by_path, lambda p: subtrees.setdefault(p, subtree(p))
                    ):
                        continue
                    if target.crate == current.crate or (
                        target.crate in crates and _publicly_named(target, name, current, by_path, crate_roots)
                    ):
                        reach(target, current.path)
    return wired
