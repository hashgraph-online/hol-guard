"""Rust side of the runtime-majority report.

Scope is the set of crates linked into the ``hol-guard-runtime`` binary (normal
and target-specific path dependencies; dev- and build-dependencies are not
linked), walked through each crate's ``mod`` tree so only compiled source files
are counted.  ``#[cfg(test)]``/``#[test]`` items are stripped by brace matching
and comments/blank lines are not counted.  Platform ``cfg`` gates other than
``test`` are all kept, so the count is the all-platform union.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

TEST_FILE_NAMES = re.compile(r"(?:_tests?\.rs|^tests?\.rs)$")
TEST_DIR_NAMES = frozenset({"tests", "testdata", "benches", "examples", "fuzz"})

_CFG_START = re.compile(r"#\s*(?P<inner>!\s*)?\[\s*(?:(?P<cfg>cfg\s*\()|test\s*\])")
_TOP_PRED = re.compile(r"(all|any|not)\s*\((.*)\)\Z", re.DOTALL)
_ATTRIBUTE = re.compile(r"#\s*!?\s*\[")
_MOD_DECL = re.compile(r"(?<![\w:])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;")
_INCLUDE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')
_PATH_ATTR = re.compile(r'path\s*=\s*"([^"]+)"')


@dataclass
class RustFileCount:
    """LOC accounting for one Rust source file."""

    path: str
    crate: str
    loc: int
    test_loc: int


@dataclass
class RustCrate:
    """A workspace crate and the source targets that link into the runtime."""

    name: str
    directory: Path
    roots: list[Path] = field(default_factory=list)


def lex_rust(source: str) -> tuple[str, bytearray]:
    """Return ``(code_text, flags)``.

    ``code_text`` blanks comments and string/char contents (keeping newlines)
    so structure can be matched; ``flags[i]`` is 1 for code, 2 for string
    content that counts as source, 0 for comments/whitespace.
    """
    n = len(source)
    flags = bytearray(n)
    code = list(source)
    i = 0

    def blank(start: int, end: int) -> None:
        for k in range(start, end):
            if code[k] != "\n":
                code[k] = " "

    while i < n:
        ch = source[i]
        two = source[i : i + 2]
        if two == "//":
            j = source.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif source.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif ch == "r" or (ch == "b" and source[i + 1 : i + 2] in {"r", '"', "'"}):
            raw = re.compile(r'b?r(#*)"').match(source, i)
            if raw and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == "_")):
                closer = '"' + raw.group(1)
                j = source.find(closer, raw.end())
                j = n if j == -1 else j + len(closer)
                _mark_string(source, flags, code, i, j)
                i = j
            elif ch == "b" and source[i + 1 : i + 2] == '"':
                j = _scan_quoted(source, i + 1, '"')
                _mark_string(source, flags, code, i, j)
                i = j
            else:
                flags[i] = 1
                i += 1
        elif ch == '"':
            j = _scan_quoted(source, i, '"')
            _mark_string(source, flags, code, i, j)
            i = j
        elif ch == "'":
            char = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'\n])'").match(source, i)
            if char:
                _mark_string(source, flags, code, i, char.end())
                i = char.end()
            else:  # lifetime or label
                flags[i] = 1
                i += 1
        else:
            if not ch.isspace():
                flags[i] = 1
            i += 1
    return "".join(code), flags


def _scan_quoted(source: str, start: int, quote: str) -> int:
    j = start + 1
    while j < len(source):
        if source[j] == "\\":
            j += 2
        elif source[j] == quote:
            return j + 1
        else:
            j += 1
    return len(source)


def _mark_string(source: str, flags: bytearray, code: list[str], start: int, end: int) -> None:
    for k in range(start, min(end, len(source))):
        if not source[k].isspace():
            flags[k] = 2
        if source[k] != "\n":
            code[k] = " "
    # Keep the quote delimiters visible as code so `mod`/`fn` scans stay aligned.


def _match_brace(code: str, open_index: int) -> int:
    depth = 0
    for k in range(open_index, len(code)):
        if code[k] == "{":
            depth += 1
        elif code[k] == "}":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(code)


def _item_end(code: str, start: int) -> int:
    """End offset of the item that begins at ``start`` (after its attributes)."""
    n = len(code)
    k = start
    while True:
        while k < n and code[k].isspace():
            k += 1
        attr = _ATTRIBUTE.match(code, k)
        if not attr:
            break
        depth, k = 0, attr.end() - 1
        while k < n:
            if code[k] == "[":
                depth += 1
            elif code[k] == "]":
                depth -= 1
                if depth == 0:
                    k += 1
                    break
            k += 1
    depth = 0
    while k < n:
        ch = code[k]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch == ";":
            return k + 1
        elif depth == 0 and ch == "{":
            end = _match_brace(code, k)
            tail = end
            while tail < n and code[tail].isspace():
                tail += 1
            return tail + 1 if tail < n and code[tail] == ";" else end
        k += 1
    return n


def _split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth, start = 0, 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def _is_test_only(predicate: str) -> bool:
    """True when a ``cfg`` predicate can only hold in a test build.

    ``all`` needs one test-only member, ``any`` needs every member test-only,
    ``not(...)`` is conservatively runtime.
    """
    predicate = predicate.strip()
    match = _TOP_PRED.match(predicate)
    if match is None:
        return predicate == "test"
    operator, inner = match.groups()
    children = _split_top_level(inner)
    if operator == "all":
        return any(_is_test_only(child) for child in children)
    if operator == "any":
        return bool(children) and all(_is_test_only(child) for child in children)
    return False


def _find_test_attribute(code: str, position: int) -> tuple[int, int, bool] | None:
    """Next ``#[cfg(<test-only>)]``/``#[test]`` as ``(start, end, is_inner)``."""
    while True:
        match = _CFG_START.search(code, position)
        if match is None:
            return None
        inner = bool(match.group("inner"))
        if not match.group("cfg"):
            return match.start(), match.end(), inner
        depth, index = 1, match.end()
        while index < len(code) and depth:
            depth += {"(": 1, ")": -1}.get(code[index], 0)
            index += 1
        close = re.compile(r"\s*\]").match(code, index)
        if depth == 0 and close and _is_test_only(code[match.end() : index - 1]):
            return match.start(), close.end(), inner
        position = match.end()


def strip_test_regions(code: str, flags: bytearray) -> list[tuple[int, int]]:
    """Mark ``#[cfg(test)]``/``#[test]`` items as non-counting; return their spans."""
    spans: list[tuple[int, int]] = []
    position = 0
    while True:
        found = _find_test_attribute(code, position)
        if found is None:
            break
        start, attribute_end, inner = found
        if inner:
            spans.append((0, len(code)))  # inner `#![cfg(test)]`: whole file
            break
        end = _item_end(code, start)
        spans.append((start, end))
        position = max(end, attribute_end)
    for start, end in spans:
        for k in range(start, end):
            flags[k] = 0
    return spans


def count_lines(source: str, flags: bytearray) -> int:
    total = 0
    offset = 0
    for line in source.split("\n"):
        if any(flags[offset : offset + len(line)]):
            total += 1
        offset += len(line) + 1
    return total


def analyze_source(source: str) -> tuple[int, int, str, bytearray]:
    """Return ``(runtime_loc, test_loc, code_text, flags_after_strip)``."""
    code, flags = lex_rust(source)
    before = count_lines(source, flags)
    strip_test_regions(code, flags)
    after = count_lines(source, flags)
    return after, before - after, code, flags


def _attribute_spans(code: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in _ATTRIBUTE.finditer(code):
        depth, k = 0, match.end() - 1
        while k < len(code):
            if code[k] == "[":
                depth += 1
            elif code[k] == "]":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        spans.append((match.start(), k + 1))
    return spans


def child_modules(source: str, code: str, flags: bytearray) -> list[tuple[str, str | None]]:
    """Out-of-line ``mod name;`` declarations that survive test stripping."""
    attributes = _attribute_spans(code)
    result: list[tuple[str, str | None]] = []
    for match in _MOD_DECL.finditer(code):
        if not flags[match.start()]:
            continue
        cursor, attr_text = match.start(), ""
        for start, end in reversed(attributes):
            if end <= cursor and not code[end:cursor].strip():
                attr_text += source[start:end]
                cursor = start
        path = _PATH_ATTR.search(attr_text)
        result.append((match.group(1), path.group(1) if path else None))
    return result


def _dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tables = [manifest.get("dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables.append(target.get("dependencies", {}))
    return [table for table in tables if isinstance(table, dict)]


def load_crate_graph(rust_root: Path) -> dict[str, tuple[Path, list[str], dict[str, Any]]]:
    """Map crate name -> (directory, linked path-dependency names, manifest)."""
    crates: dict[str, tuple[Path, dict[str, Any]]] = {}
    for manifest_path in sorted((rust_root / "crates").glob("*/Cargo.toml")):
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        crates[str(manifest["package"]["name"])] = (manifest_path.parent, manifest)
    graph: dict[str, tuple[Path, list[str], dict[str, Any]]] = {}
    for name, (directory, manifest) in crates.items():
        deps: list[str] = []
        for table in _dependency_tables(manifest):
            for dep_name, spec in table.items():
                if isinstance(spec, dict) and "path" in spec:
                    target = (directory / str(spec["path"])).resolve()
                    for other, (other_dir, _) in crates.items():
                        if other_dir.resolve() == target:
                            deps.append(other)
                elif dep_name in crates:
                    deps.append(dep_name)
        graph[name] = (directory, sorted(set(deps)), manifest)
    return graph


def linked_crates(graph: dict[str, tuple[Path, list[str], dict[str, Any]]], binary_crate: str) -> list[str]:
    seen: list[str] = []
    stack = [binary_crate]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.append(current)
        stack.extend(graph[current][1])
    return sorted(seen)


def crate_roots(directory: Path, manifest: dict[str, Any], *, binary: bool) -> list[Path]:
    if binary:
        roots = [directory / str(item.get("path", "src/main.rs")) for item in manifest.get("bin", [])]
        return roots or [directory / "src/main.rs"]
    lib = manifest.get("lib", {})
    return [directory / str(lib.get("path", "src/lib.rs"))]


def walk_module_tree(root_file: Path) -> tuple[list[Path], list[str]]:
    """Return source files reachable through out-of-line ``mod`` declarations."""
    seen: dict[Path, None] = {}
    unresolved: list[str] = []
    stack = [root_file.resolve()]
    while stack:
        current = stack.pop()
        if current in seen or not current.is_file():
            continue
        seen[current] = None
        source = current.read_text(encoding="utf-8")
        _, _, code, flags = analyze_source(source)
        directory = current.parent
        owns_directory = current.name in {"lib.rs", "main.rs", "mod.rs"}
        child_dir = directory if owns_directory else directory / current.stem
        for name, explicit in child_modules(source, code, flags):
            candidates = (
                [directory / explicit]
                if explicit
                else [child_dir / f"{name}.rs", child_dir / name / "mod.rs", directory / f"{name}.rs"]
            )
            found = next((candidate for candidate in candidates if candidate.is_file()), None)
            if found is None:
                unresolved.append(f"{current}:{name}")
            else:
                stack.append(found.resolve())
        for match in _INCLUDE.finditer(source):
            if flags[match.start()] != 1:  # comment, string literal, or cfg(test) region
                continue
            target = directory / match.group(1)
            if target.is_file():
                stack.append(target.resolve())
    return sorted(seen), unresolved


def classify_unlinked(relative: str) -> str:
    parts = relative.split("/")
    name = parts[-1]
    if any(part in TEST_DIR_NAMES for part in parts[:-1]) or TEST_FILE_NAMES.search(name):
        return "tests"
    if name == "build.rs":
        return "build_script"
    if "src" in parts and "bin" in parts[parts.index("src") + 1 : -1]:
        return "unlinked_binary_target"
    return "not_in_module_tree"


def match_any(path: str, patterns: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in patterns:
        if fnmatch.fnmatchcase(path, str(entry["path"])):
            return entry
    return None


def measure_rust(
    repo: Path, scope: dict[str, Any]
) -> tuple[list[RustFileCount], list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    """Return per-file counts, exclusions, non-runtime totals and crate metadata."""
    rust_root = repo / str(scope["workspace"])
    graph = load_crate_graph(rust_root)
    binary_crate = str(scope["binary_crate"])
    linked = linked_crates(graph, binary_crate)
    counts: list[RustFileCount] = []
    exclusions: list[dict[str, Any]] = []
    totals = {"tests": 0, "generated": 0, "adapters": 0, "unlinked": 0}
    path_exclusions = list(scope.get("exclude_paths", []))
    unresolved: list[str] = []
    for name in sorted(graph):
        directory, _, manifest = graph[name]
        files_in_crate = sorted(
            path for path in directory.rglob("*.rs") if "target" not in path.relative_to(directory).parts
        )
        reachable: dict[Path, None] = {}
        if name in linked:
            roots = crate_roots(directory, manifest, binary=name == binary_crate)
            for root in roots:
                found, missing = walk_module_tree(root)
                unresolved.extend(missing)
                reachable.update(dict.fromkeys(found))
        for path in files_in_crate:
            relative = path.relative_to(repo).as_posix()
            source = path.read_text(encoding="utf-8")
            loc, test_loc, _, _ = analyze_source(source)
            totals["tests"] += test_loc
            if path.resolve() in reachable:
                override = match_any(relative, path_exclusions)
                if TEST_FILE_NAMES.search(path.name) or any(
                    p in TEST_DIR_NAMES for p in path.relative_to(directory).parts[:-1]
                ):
                    totals["tests"] += loc
                    exclusions.append(_exclusion(relative, "tests", "test-only file name or directory", loc))
                elif override:
                    totals["unlinked"] += loc
                    exclusions.append(_exclusion(relative, str(override["category"]), str(override["reason"]), loc))
                else:
                    counts.append(RustFileCount(relative, name, loc, test_loc))
                continue
            category = classify_unlinked(relative) if name in linked else "crate_not_linked"
            reason = {
                "tests": "test-only directory or file name",
                "build_script": "build-time script, not linked into the runtime binary",
                "unlinked_binary_target": "separate binary target (authoring or tooling), not hol-guard-runtime",
                "not_in_module_tree": "not reachable from the crate mod tree (cfg(test)-only or orphan)",
                "crate_not_linked": "crate is not a normal/target dependency of the runtime binary",
            }[category]
            if category == "tests":
                totals["tests"] += loc
            else:
                totals["unlinked"] += loc
            exclusions.append(_exclusion(relative, category, reason, loc))
    meta = {"linked_crates": linked, "binary_crate": binary_crate, "unresolved_modules": sorted(unresolved)}
    return counts, exclusions, totals, meta


def _exclusion(path: str, category: str, reason: str, loc: int) -> dict[str, Any]:
    return {"language": "rust", "path": path, "category": category, "reason": reason, "loc": loc}
