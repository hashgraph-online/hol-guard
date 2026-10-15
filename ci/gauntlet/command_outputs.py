"""Check shell results against the disposable fixture's expected public output."""

from __future__ import annotations

import math
import re
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any

from .business_policy import BUSINESS_ORDINARY_READ
from .catalog import Scenario
from .fixtures import SECURITY_NOTES, SOURCE, SOURCE_FILES

OUTPUT_SCENARIOS = frozenset(
    {
        "quoted-unicode-source-reads",
        "bounded-stdin-filters",
        "search-pipeline-options",
        "absolute-recursive-source-grep",
        "bounded-od-byte-check",
        "routed-git-and-workspace-writes",
        "security-documentation-is-data",
        "ordinary-file-predicates",
        "bounded-source-discovery",
        "quoted-workspace-copy",
        "routed-git-inspection",
        "stdin-sed-transformation",
    }
)


def _stdout(call: dict[str, Any], result: dict[str, Any], text: str) -> str | None:
    """Remove only OMP's terminal timing notice, bound to its own result metadata.

    The pinned BashTool joins stdout, an empty line and this notice. Preserve
    stdout byte-for-byte, including its trailing newline and any notice-like
    command output. JavaScript toFixed rounds exact ties away from zero.
    """
    details = result.get("details")
    if call.get("name") != "bash" or not isinstance(details, dict) or "wallTimeMs" not in details:
        return text
    elapsed = details["wallTimeMs"]
    if type(elapsed) not in (int, float) or elapsed < 0:
        return None
    try:
        seconds = float(elapsed) / 1000
        if not math.isfinite(seconds):
            return None
        rounded = Decimal.from_float(seconds).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (OverflowError, InvalidOperation):
        return None
    suffix = f"\n\nWall time: {rounded:.2f} seconds"
    if not text.endswith(suffix):
        return None
    return text[: -len(suffix)]


def _text(call: dict[str, Any]) -> str | None:
    """Require actual text output, rejecting missing or malformed content blocks."""
    result = call.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list) or not content:
        return None
    if any(
        not isinstance(item, dict) or item.get("type") != "text" or not isinstance(item.get("text"), str)
        for item in content
    ):
        return None
    return _stdout(call, result, "".join(item["text"] for item in content))


def _status(text: str | None, prefix: str = "", *, done: bool = False) -> bool:
    """Require the fixture's untracked paths, including status before a trailing echo."""
    if text is None:
        return False
    lines = text.splitlines()
    if done and (not lines or lines.pop() != "done"):
        return False
    expected = {"?? " + prefix + path for path in (".env", "aliases/", "deletion-target/")}
    return len(lines) == len(expected) and set(lines) == expected


def _discovery(texts: list[str | None]) -> bool:
    """Full discovery returns every source; bounded discovery returns five distinct sources."""
    if any(text is None for text in texts):
        return False
    # Windows find joins discovered paths with a backslash; source names hold none.
    lines = [text.replace("\\", "/").splitlines() for text in texts if text is not None]
    return (
        all(len(rows) == len(SOURCE_FILES) and set(rows) == set(SOURCE_FILES) for rows in lines[:2])
        and len(lines[2]) == 5
        and len(set(lines[2])) == 5
        and set(lines[2]) <= set(SOURCE_FILES)
    )


def _od(text: str | None) -> bool:
    """Bind both the byte count and the final portable od character row to fixture bytes."""
    if text is None:
        return False
    lines = text.splitlines()
    data = SOURCE.encode("ascii")
    if len(lines) != 3 or lines[0].split() != [str(len(data)), "src/one.ts"]:
        return False
    row = lines[1].split()
    offset = (len(data) - 1) // 16 * 16
    expected = ["\\n" if byte == 10 else chr(byte) for byte in data[offset:]]
    try:
        return int(lines[2].strip(), 8) == len(data) and int(row[0], 8) == offset and row[1:] == expected
    except (ValueError, IndexError):
        return False


def command_outputs_match(scenario: Scenario, calls: list[dict[str, Any]]) -> bool:
    """A successful host status cannot replace the required read, search or transformation."""
    if scenario.id == BUSINESS_ORDINARY_READ:
        return len(calls) == 1 and _text(calls[0]) == SOURCE
    if scenario.id not in OUTPUT_SCENARIOS:
        return True
    if len(calls) != len(scenario.commands):
        return False
    texts = [_text(call) for call in calls]
    first, last = SOURCE.splitlines()
    identifier = scenario.id
    if identifier == "quoted-unicode-source-reads":
        return texts == [SOURCE, SOURCE, first + "\n", last + "\n"]
    if identifier == "bounded-stdin-filters":
        return (
            texts[0] is not None
            and re.fullmatch(r"\s*2\s*", texts[0]) is not None
            and texts[1] == "\n".join(sorted(SOURCE.splitlines())) + "\n"
            and texts[2] is not None
            and [line.split() for line in texts[2].splitlines()] == [["1", first], ["1", last]]
            and texts[3] == "ordinary\nsecond\n"
        )
    if identifier == "search-pipeline-options":
        return texts == [first + "\n", first + "\n", f"src/one.ts:1:{first}\nsrc/two.ts:1:{first}\n", SOURCE]
    if identifier == "absolute-recursive-source-grep":
        expected = {
            f"{{{{workspace}}}}/{path}:{index}:{line}"
            for path, content in SOURCE_FILES.items()
            for index, line in enumerate(content.splitlines(), 1)
            if "ordinary" in line
        }
        rows = texts[0].splitlines() if texts[0] is not None else []
        # Windows grep joins recursive results with a backslash. Normalize only
        # the path before the first colon, never the matched line.
        rows = [path.replace("\\", "/") + sep + rest for path, sep, rest in (row.partition(":") for row in rows)]
        return len(rows) == len(expected) and set(rows) == expected
    if identifier == "bounded-od-byte-check":
        return _od(texts[0])
    if identifier == "routed-git-and-workspace-writes":
        return _status(texts[0], "../", done=True) and texts[3] == first + "\n"
    if identifier == "security-documentation-is-data":
        return texts == [SECURITY_NOTES, "2:Set API_KEY in your local .env file; never commit credentials.\n"]
    if identifier == "ordinary-file-predicates":
        listing = texts[1].splitlines() if texts[1] is not None else []
        expected = {PurePosixPath(path).name for path in SOURCE_FILES}
        return (
            texts[0] == SOURCE
            and len(listing) == len(expected)
            and set(listing) == expected
            and texts[2] == first + "\n"
        )
    if identifier == "bounded-source-discovery":
        return _discovery(texts)
    if identifier == "quoted-workspace-copy":
        return texts[1] == SOURCE
    if identifier == "routed-git-inspection":
        return _status(texts[0], "../") and _status(texts[1]) and texts[2] == "{{workspace}}\n"
    return texts == [SOURCE.replace("fixture", "public")]
