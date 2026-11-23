"""The native local-CLI regroup step must read and move what Python does.

``guard_store_schema_local_cli_regroup.rs`` keeps its own copy of the
non-recognition risk summaries and the statements
``regroup_pending_connector_reviews`` runs. These tests fail when either side
changes until the other follows.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from codex_plugin_scanner.guard import store_local_cli_regroup as regroup

ROOT = Path(__file__).resolve().parents[1]
STEP = ROOT / "rust" / "crates" / "guard-runtime" / "src" / "guard_store_schema_local_cli_regroup.rs"


def _normal(text: str) -> str:
    return " ".join(re.sub(r"\?\d", "?", text).split())


def _rust_const(name: str) -> list[str]:
    source = STEP.read_text(encoding="utf-8")
    match = re.search(rf"const {name}: [^=]+=\s*(.*?);\n", source, re.S)
    assert match is not None, name
    return [re.sub(r"\\\n\s*", "", text) for text in re.findall(r'"((?:[^"\\]|\\.|\\\n)*)"', match.group(1))]


def _python_source() -> str:
    source = inspect.getsource(regroup)
    return _normal(re.sub(r'"\s*\n\s*"', "", source))


def test_native_risk_summaries_match_python() -> None:
    summaries = [text.replace("\\'", "'") for text in _rust_const("NON_RECOGNITION_RISK_SUMMARIES")]
    assert tuple(summaries) == regroup.NON_RECOGNITION_RISK_SUMMARIES


def test_native_statements_are_python_statements() -> None:
    python = _python_source()
    for name in ("OBSERVATIONS", "DECIDED", "MOVE"):
        (statement,) = _rust_const(name)
        assert _normal(statement) in python, name
    (reviews,) = _rust_const("REVIEWS")
    # Python builds the risk-summary placeholders with an f-string.
    native_marks = "(" + ", ".join("?" for _ in regroup.NON_RECOGNITION_RISK_SUMMARIES) + ")"
    assert _normal(reviews).replace(native_marks, "({marks})") in python


def test_native_command_limit_matches_python() -> None:
    source = STEP.read_text(encoding="utf-8")
    limit = re.search(r"const MAX_COMMAND_CHARS: i64 = (\d+);", source)
    assert limit is not None
    assert int(limit.group(1)) == regroup._MAX_COMMAND_CHARS  # pyright: ignore[reportPrivateUsage]
