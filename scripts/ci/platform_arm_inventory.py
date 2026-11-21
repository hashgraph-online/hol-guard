#!/usr/bin/env python3
"""Keep every non-Unix behaviour arm in the Rust tree under standing review.

Guard's runtime compiles a `#[cfg(not(unix))]` arm in place of the Unix one on
Windows. Twice now a containment fix shipped with its behaviour behind
`#[cfg(unix)]` and its proof behind `#![cfg(unix)]`, so the Windows arm never
entered a test binary and the platform gap stayed invisible:

* `guard-runtime/src/hook_direct_contained.rs` defers every contained route on
  Windows (PR #5397), proven only by `#![cfg(unix)]` test files.
* `guard-command/src/pretool/contained_wrapper.rs::sibling_project_root`
  returns `None` on Windows (PR #5200), proven only by the `#![cfg(unix)]`
  integration test `tests/pretool_sibling_repository_writes.rs`.

Whether a given arm is reached by some test cannot be decided by reading the
source: a private helper is usually exercised through a public entry point, and
an integration test names neither. So this gate does not guess. It requires
that every non-Unix arm is named in `ci/platform_arms.json` with a verdict a
reviewer wrote, and fails when an arm appears, moves or changes signature
without one, or when an entry no longer matches any arm.

An arm is in scope when its predicate names `unix` and compiles off Unix: the
predicate is parsed and evaluated rather than matched as text, so
`not(unix)`, `not(any(unix, windows))` and `all(not(unix), feature = "x")` are
all found and no spelling of the same condition gets past the gate. `cfg!(..)`
expressions are read too, in either polarity: a runtime branch written as
`if cfg!(not(unix))` or `if !cfg!(unix)` is the same platform difference, and
unlike an attribute it has no second arm for the gate to find on its own.

Verdicts:

``posix-primitive``
    The arm substitutes a Windows equivalent for a POSIX-only concept (mode
    bits, uid/gid, unix sockets, signals, symlink semantics). The platform
    difference is the point.
``windows-equivalent``
    A real Windows implementation, not a stub.
``windows-unsupported``
    The capability does not exist on Windows yet and the arm fails closed, so
    the caller falls back to review or deny. Safe, but it is what turns benign
    Windows work into an approval prompt.
``windows-permissive``
    The arm returns the permissive value where Unix proves something. Every one
    of these needs a reason why skipping the proof is sound on Windows.
``other-platform``
    `#[cfg(all(not(unix), not(windows)))]`: Windows takes an arm of its own, so
    this one only covers platforms Guard does not ship for.

Usage::

    python3 scripts/ci/platform_arm_inventory.py            # check
    python3 scripts/ci/platform_arm_inventory.py --write    # refresh entries
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
CRATES = Path("rust/crates")
INVENTORY = Path("ci/platform_arms.json")
VERDICTS = (
    "posix-primitive",
    "windows-equivalent",
    "windows-unsupported",
    "windows-permissive",
    "other-platform",
)
UNREVIEWED = "unreviewed"

# A whole-line `#[cfg(..)]` attribute. The predicate is parsed below rather
# than matched as text, so no spelling of "off Unix" gets past the gate.
ATTRIBUTE = re.compile(r"^(?P<indent>\s*)#\[cfg\((?P<cfg>.*)\)\]\s*$")
# `if cfg!(not(unix))` is the same platform difference written as an
# expression, and reaches the same runtime branch. The predicate is read by
# balancing brackets rather than by regex, so `cfg!(any(unix, windows))` keeps
# its whole predicate instead of stopping at the first `)`.
MACRO = re.compile(r"\bcfg!\(")
SKIPPED = re.compile(r"^\s*(?:#\[|//[/!]?)")
WHITESPACE = re.compile(r"\s+")
# How far a multi-line item signature may run before the opening brace.
SIGNATURE_LINES = 16
# How far a bare block may run before its fingerprint stops reading.
BLOCK_LINES = 200
ATOM = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def macro_predicate(line: str) -> str | None:
    """The predicate of the first `cfg!(..)` on `line`, brackets balanced."""
    match = MACRO.search(line)
    if match is None:
        return None
    depth, start = 1, match.end()
    for position in range(start, len(line)):
        if line[position] in "([":
            depth += 1
        elif line[position] in ")]":
            depth -= 1
            if depth == 0:
                return line[start:position]
    return None


def split(predicate: str) -> list[str]:
    """`a, b(c, d)` as `["a", "b(c, d)"]`: commas outside brackets only."""
    parts, depth, start = [], 0, 0
    for position, character in enumerate(predicate):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif character == "," and depth == 0:
            parts.append(predicate[start:position])
            start = position + 1
    parts.append(predicate[start:])
    return [part.strip() for part in parts if part.strip()]


def evaluate(predicate: str, **atoms: bool) -> bool:
    """A `cfg` predicate under the given atoms.

    An atom the caller does not name is true, so a predicate narrowed by a
    feature or an architecture still counts as reachable. A malformed or
    unparseable predicate is true for the same reason: the gate's job is to
    over-collect arms for review, never to quietly drop one.
    """
    predicate = predicate.strip()
    for operator in ("all", "any", "not"):
        if predicate.startswith(f"{operator}(") and predicate.endswith(")"):
            inner = split(predicate[len(operator) + 1 : -1])
            results = [evaluate(part, **atoms) for part in inner]
            if operator == "all":
                return all(results)
            if operator == "any":
                return any(results)
            return not results[0] if len(results) == 1 else True
    if ATOM.match(predicate):
        return atoms.get(predicate, True)
    return True


def off_unix(predicate: str) -> bool:
    """Whether this predicate selects a behaviour arm that replaces a Unix one.

    It has to name `unix`, hold with `unix` unset, and not hold with `unix`
    set. Naming `unix` is what keeps the gate to arms that substitute for Unix
    behaviour rather than every `#[cfg(windows)]` block in the tree. `test` is
    unset on both sides, so `all(test, not(unix))` — a test that only runs off
    Unix, which is proof rather than behaviour — drops out, while
    `any(not(unix), test)` stays: it compiles into an ordinary non-Unix build.
    """
    if not re.search(r"\bunix\b", predicate):
        return False
    off = evaluate(predicate, unix=False, test=False, windows=True) or evaluate(
        predicate, unix=False, test=False, windows=False
    )
    return off and not evaluate(predicate, unix=True, test=False, windows=False)


def branching(predicate: str) -> bool:
    """Whether a `cfg!(..)` expression is a platform branch to review.

    Naming `unix` is enough, in either polarity. An attribute has a separate
    non-Unix arm for the gate to find, so only that arm needs an entry; an
    expression has no second arm — `if cfg!(unix) { .. } else { .. }` and
    `cfg!(not(unix)) || proven(path)` both decide Windows behaviour inside one
    function, and the function is what a reviewer has to read either way.
    """
    return bool(re.search(r"\bunix\b", predicate))


SCOPE = re.compile(
    r"^\s*(?:pub\b[^;{]*?)?(?:async\s+|unsafe\s+|default\s+)*"
    r"(?P<kind>fn|impl|mod|trait|struct|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
DECLARATION = re.compile(
    r"^\s*(?:pub\b[^;{]*?)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+|default\s+)*"
    r"(?:fn|mod|impl|struct|enum|trait|type|const|static|use)\b"
)


def declaration(lines: list[str], start: int) -> str:
    """The item's declaration, joined and normalised so a reformat is stable."""
    parts: list[str] = []
    for line in lines[start : start + SIGNATURE_LINES]:
        parts.append(line.strip())
        if any(character in parts[-1] for character in "{;="):
            break
    joined = WHITESPACE.sub(" ", " ".join(parts))
    return joined[: terminator(joined)].strip()


def terminator(joined: str) -> int:
    """Where the declaration ends: the first `{`, `;` or `=` outside brackets.

    `const NAMES: [&str; 3]` carries a `;` inside its type, so a plain search
    would cut the name off its type and make the entry unreadable.
    """
    depth = 0
    for position, character in enumerate(joined):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif depth == 0 and character in "{;=":
            return position
    return len(joined)


def enclosing(lines: list[str], start: int) -> str:
    """The nearest enclosing item above `start`, for an arm that is a bare block.

    A `#[cfg(not(unix))] { .. }` block inside a function has no declaration of
    its own, so it is named after the item it stands in.
    """
    for index in range(start, -1, -1):
        match = SCOPE.match(lines[index])
        if match is not None:
            return f"{match.group('kind')} {match.group('name')}"
    return "<file scope>"


def signature(lines: list[str], start: int) -> str:
    """A name for the arm at `start` that survives reformatting."""
    if DECLARATION.match(lines[start]):
        return declaration(lines, start)
    return f"{enclosing(lines, start)} -- non-Unix block"


OPENING, CLOSING = "([{", ")]}"


def code_only(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """`line` with comments and literals removed, and the block-comment state.

    Brackets are counted to find where an arm ends, so only brackets that are
    code may count. Prose such as `// 1) probe the handle` and literals such as
    `'('` or `"["` are unbalanced often enough that counting them would end the
    digest early, leaving whatever follows unreviewed.
    """
    kept: list[str] = []
    index, length = 0, len(line)
    while index < length:
        character = line[index]
        if in_block_comment:
            if line.startswith("*/", index):
                in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        if line.startswith("//", index):
            break
        if line.startswith("/*", index):
            in_block_comment = True
            index += 2
            continue
        if character == '"':
            index += 1
            while index < length:
                if line[index] == "\\":
                    index += 2
                    continue
                if line[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if character == "'":
            # A lifetime (`'a`) carries no closing quote, so only a real char
            # literal is skipped; anything else is left to be read as code.
            closing = line.find("'", index + 3 if line.startswith("'\\", index) else index + 2)
            if closing != -1 and closing - index <= 4:
                index = closing + 1
                continue
            index += 1
            continue
        kept.append(character)
        index += 1
    return "".join(kept), in_block_comment


def fingerprint(lines: list[str], start: int) -> str:
    """A short digest of the arm's own source.

    Every arm carries one. A bare block is keyed by its position among the
    blocks of the item it sits in, so without a digest, inserting a block ahead
    of a reviewed one would hand the newcomer the existing verdict. A
    declaration is keyed by its own name, which that cannot happen to, but its
    body can still be rewritten under a verdict written for what it used to do:
    a `windows-unsupported` stub that fails closed becomes one that returns
    `true`, with the reason left intact. Source that changed is source to
    review again either way.

    The digest ends where the item does, at the brace that closes a body or at
    the `;` of a declaration that has none, so a `mod` or a `use` is not keyed
    on whatever lines happen to follow it.
    """
    collected: list[str] = []
    depth, in_block_comment = 0, False
    for line in lines[start : start + BLOCK_LINES]:
        collected.append(WHITESPACE.sub(" ", line.strip()))
        code, in_block_comment = code_only(line, in_block_comment)
        depth += sum(code.count(character) for character in OPENING)
        depth -= sum(code.count(character) for character in CLOSING)
        if depth <= 0 and any(character in code for character in "};"):
            break
    body = " ".join(part for part in collected if part and not part.startswith("//"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]


def test_module(lines: list[str]) -> set[int]:
    """Line numbers inside an inline `#[cfg(test)] mod tests { .. }`.

    A `*_tests.rs` file is skipped by name; a test module written in the same
    file as the code it proves has to be skipped by extent, or its own
    `cfg!(unix)` assertions read as behaviour arms.
    """
    inside: set[int] = set()
    for index, line in enumerate(lines):
        if line.strip() != "#[cfg(test)]":
            continue
        cursor = index + 1
        while cursor < len(lines) and SKIPPED.match(lines[cursor]):
            cursor += 1
        if cursor >= len(lines) or not re.match(r"\s*(?:pub\b[^;{]*?)?mod\b", lines[cursor]):
            continue
        depth, opened = 0, False
        while cursor < len(lines):
            inside.add(cursor)
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            opened = opened or "{" in lines[cursor]
            if opened and depth <= 0:
                break
            cursor += 1
    return inside


def record(found: list[dict[str, str]], relative: str, item: str, cfg: str, body: str) -> None:
    """Add an arm, numbering a repeat of an item that already appeared."""
    repeats = sum(1 for seen in found if seen["file"] == relative and seen["item"].startswith(item))
    if repeats:
        item = f"{item} #{repeats + 1}"
    found.append({"file": relative, "item": item, "cfg": WHITESPACE.sub(" ", cfg).strip(), "body": body})


def arms(root: Path) -> list[dict[str, str]]:
    """Every non-Unix behaviour arm under `root`, in path order."""
    found: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.rs")):
        relative = path.relative_to(root.parent.parent).as_posix()
        if "/src/" not in relative or path.name.endswith("_tests.rs"):
            continue
        text = path.read_text(encoding="utf-8")
        if "unix" not in text:
            continue
        lines = text.splitlines()
        tests = test_module(lines)
        for index, line in enumerate(lines):
            if index in tests:
                continue
            attribute = ATTRIBUTE.match(line)
            if attribute is not None:
                if not off_unix(attribute.group("cfg")):
                    continue
                cursor = index + 1
                while cursor < len(lines) and SKIPPED.match(lines[cursor]):
                    cursor += 1
                if cursor >= len(lines):
                    continue
                item = signature(lines, cursor)
                record(found, relative, item, attribute.group("cfg"), fingerprint(lines, cursor))
                continue
            macro = macro_predicate(line)
            if macro is None or SKIPPED.match(line) or not branching(macro):
                continue
            item = f"{enclosing(lines, index)} -- cfg! expression"
            record(found, relative, item, macro, fingerprint(lines, index))
    return found


def key(entry: dict[str, str]) -> tuple[str, str]:
    return entry["file"], entry["item"]


def load(inventory: Path) -> list[dict[str, str]]:
    document = json.loads(inventory.read_text(encoding="utf-8"))
    if document.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit(f"{inventory}: unsupported schema_version")
    entries = document.get("arms")
    if not isinstance(entries, list):
        raise SystemExit(f"{inventory}: `arms` must be a list")
    return entries


def problems(found: list[dict[str, str]], reviewed: list[dict[str, str]]) -> list[str]:
    """Every difference between the tree and the reviewed inventory."""
    seen: dict[tuple[str, str], dict[str, str]] = {}
    messages: list[str] = []
    for entry in reviewed:
        if not isinstance(entry, dict) or not {"file", "item", "cfg", "verdict", "note"} <= set(entry):
            messages.append(f"inventory entry is missing a required field: {entry!r}")
            continue
        if entry["verdict"] not in VERDICTS:
            messages.append(f"{entry['file']}: unknown verdict {entry['verdict']!r}")
        if not entry["note"].strip() or entry["note"].strip() == UNREVIEWED:
            messages.append(f"{entry['file']}: {entry['item']}: the verdict has no reason")
        if key(entry) in seen:
            messages.append(f"{entry['file']}: duplicate entry for {entry['item']}")
        seen[key(entry)] = entry
    current = {key(arm) for arm in found}
    for arm in found:
        reviewed_arm = seen.get(key(arm))
        if reviewed_arm is None:
            continue
        if reviewed_arm.get("cfg") != arm["cfg"]:
            messages.append(
                f"{arm['file']}: `{arm['item']}` is now `#[cfg({arm['cfg']})]`; review the entry and update its `cfg`."
            )
        if reviewed_arm.get("body") != arm.get("body"):
            messages.append(
                f"{arm['file']}: the block behind `{arm['item']}` changed; review the entry and update its `body`."
            )
    for arm in found:
        if key(arm) not in seen:
            messages.append(
                f"{arm['file']}: new non-Unix arm `{arm['item']}` is not reviewed.\n"
                f"    Run `python3 {Path(__file__).as_posix()} --write`, then give the new entry a"
                " verdict and a reason saying whether the Windows arm is a correct platform"
                " difference or a silent gap, and how it is proven off Unix."
            )
    for entry in reviewed:
        if key(entry) not in current:
            messages.append(f"{entry['file']}: reviewed arm `{entry['item']}` no longer exists; drop the entry.")
    return messages


PLACEHOLDER = {"verdict": "windows-unsupported", "note": UNREVIEWED}


def carried(saved: dict[str, str] | None, arm: dict[str, str]) -> dict[str, str]:
    """The verdict an arm keeps across a refresh.

    Only an arm that still reads the same way keeps one. When the predicate or
    the block behind it changed, the Windows behaviour under review changed
    with it, so the entry goes back to unreviewed and the gate keeps failing
    until a reviewer writes a reason for what it does now.
    """
    if saved is None or saved.get("cfg") != arm["cfg"]:
        return dict(PLACEHOLDER)
    # An entry written before fingerprints existed carries none, and adopts the
    # one it is given. Afterwards a fingerprint that moved resets the verdict.
    if "body" in saved and saved.get("body") != arm.get("body"):
        return dict(PLACEHOLDER)
    return saved


def write(inventory: Path, found: list[dict[str, str]], reviewed: list[dict[str, str]]) -> None:
    """Keep every unchanged verdict and add a placeholder for each new arm."""
    kept = {key(entry): entry for entry in reviewed if isinstance(entry, dict) and {"file", "item"} <= set(entry)}
    merged = [{**carried(kept.get(key(arm)), arm), **arm} for arm in found]
    document = {
        "schema_version": SCHEMA_VERSION,
        "comment": (
            "Every non-Unix behaviour arm in rust/crates/*/src — `#[cfg(..)]` attribute or"
            " `cfg!(..)` expression — with the verdict a reviewer gave it."
            " scripts/ci/platform_arm_inventory.py keeps this list honest."
        ),
        "arms": merged,
    }
    inventory.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--write", action="store_true", help="refresh the inventory in place")
    arguments = parser.parse_args(argv)
    crates, inventory = arguments.root / CRATES, arguments.root / INVENTORY
    found = arms(crates)
    reviewed = load(inventory) if inventory.exists() else []
    if arguments.write:
        write(inventory, found, reviewed)
        print(f"{inventory}: {len(found)} arms")
        return 0
    messages = problems(found, reviewed)
    for message in messages:
        print(message, file=sys.stderr)
    if messages:
        print(f"\n{len(messages)} unreviewed non-Unix arm(s).", file=sys.stderr)
        return 1
    print(f"{len(found)} non-Unix arms, all reviewed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
