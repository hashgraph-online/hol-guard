"""Bounded source labels and timings; never frames, arguments or callers."""

from __future__ import annotations

import math
import re
from pathlib import Path

ROOT_LABELS = frozenset({"installed", "tooling", "stdlib", "dependencies"})
GENERATED = frozenset({"<genexpr>", "<listcomp>", "<dictcomp>", "<setcomp>", "<module>"})
FROZEN = frozenset(
    f"<frozen {name}>"
    for name in (
        "importlib._bootstrap",
        "importlib._bootstrap_external",
        "os",
        "posixpath",
        "abc",
        "_collections_abc",
        "codecs",
        "genericpath",
    )
)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
BUILTIN = re.compile(r"<built-in method ([A-Za-z_][A-Za-z0-9_.]{0,127})>")
METHOD = re.compile(r"<method '([A-Za-z_][A-Za-z0-9_]{0,63})' of '([A-Za-z_][A-Za-z0-9_.]{0,127})' objects>")


def source_label(frame, roots):
    filename, line, function = frame
    if filename == "~":
        if match := BUILTIN.fullmatch(function):
            return {"root": "builtin", "module": "builtin", "function": match[1], "line": 0}
        if match := METHOD.fullmatch(function):
            return {"root": "builtin", "module": "builtin", "function": f"{match[2]}.{match[1]}", "line": 0}
        return None
    if not (IDENTIFIER.fullmatch(function) or function in GENERATED):
        return None
    if filename in FROZEN:
        return {"root": "stdlib", "module": filename, "function": function, "line": line}
    path = Path(filename)
    if not path.is_absolute():
        return None
    for label, root in roots.items():
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        # Only installed/tool source module names are emitted. Traversal and
        # arbitrary executable/data filenames never become report fields.
        if (
            relative.suffix != ".py"
            or ".." in relative.parts
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", part) for part in relative.parts)
        ):
            return None
        return {"root": label, "module": relative.as_posix(), "function": function, "line": line}
    return None


def summarize_profile(stats, roots, *, limit=80):
    if set(roots) - ROOT_LABELS or not 1 <= limit <= 200:
        raise ValueError("profile reporting contract changed")
    values = []
    total_self = unmapped_self = 0.0
    unmapped = 0
    calls = 0
    for frame, (primitive, total, own, cumulative, _callers) in stats.items():
        if type(primitive) is not int or type(total) is not int or primitive < 0 or total < primitive:
            raise ValueError("invalid profile call counts")
        if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in (own, cumulative)):
            raise ValueError("invalid profile timing")
        if type(frame[1]) is not int or frame[1] < 0:
            raise ValueError("invalid profile source line")
        total_self += own
        calls += total
        label = source_label(frame, roots)
        if label is None:
            unmapped += 1
            unmapped_self += own
            continue
        values.append(
            {
                **label,
                "primitive_calls": primitive,
                "total_calls": total,
                "self_elapsed_seconds": own,
                "cumulative_elapsed_seconds": cumulative,
            }
        )
    values.sort(key=lambda value: (-value["self_elapsed_seconds"], value["root"], value["module"], value["function"]))
    return {
        "functions": len(stats),
        "total_calls": calls,
        "total_self_elapsed_seconds": total_self,
        "unmapped_functions": unmapped,
        "unmapped_self_elapsed_seconds": unmapped_self,
        "retained_functions": min(limit, len(values)),
        "top_by_self_elapsed": values[:limit],
    }
