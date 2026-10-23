from __future__ import annotations

import ast
import re
from pathlib import Path

from scripts.native_resident_stop_bound import RESIDENT_STOP_TIMEOUT_SECONDS

_ROOT = Path(__file__).resolve().parents[1]
_RUNTIME = _ROOT / "rust/crates/guard-runtime/src"
_TIMEOUT_KEYWORDS = frozenset({"timeout", "timeout_seconds"})
# Process start and the runtime self-digest happen before the runtime's own
# stop bounds begin, so a caller needs real headroom beyond them.
_STARTUP_HEADROOM_SECONDS = 2.0


def _runtime_seconds(file_name: str, constant: str) -> float:
    source = (_RUNTIME / file_name).read_text(encoding="utf-8")
    match = re.search(rf"const {constant}: Duration = Duration::from_secs\((\d+)\);", source)
    assert match is not None, f"{constant} moved; update this check"
    return float(match.group(1))


def _minimum_stop_timeout() -> float:
    stop = _runtime_seconds("managed_resident.rs", "MANAGED_STOP_TIMEOUT")
    quiesce = _runtime_seconds("managed_resident_exit.rs", "SUPERVISOR_QUIESCE_TIMEOUT")
    return stop + quiesce + _STARTUP_HEADROOM_SECONDS


def _literal_stop_timeouts(source: str) -> list[float]:
    timeouts: list[float] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        names_stop = any(
            isinstance(inner, ast.Constant) and inner.value == "resident-stop"
            for argument in node.args
            for inner in ast.walk(argument)
        )
        if not names_stop:
            continue
        for keyword in node.keywords:
            value = keyword.value
            if (
                keyword.arg in _TIMEOUT_KEYWORDS
                and isinstance(value, ast.Constant)
                and isinstance(value.value, int | float)
                and not isinstance(value.value, bool)
            ):
                timeouts.append(float(value.value))
    return timeouts


def test_harness_stop_timeout_outlasts_the_runtime_stop_bounds() -> None:
    assert _minimum_stop_timeout() <= RESIDENT_STOP_TIMEOUT_SECONDS


def test_literal_stop_timeouts_are_found_in_every_call_shape() -> None:
    source = (
        'subprocess.run((runtime, "resident-stop"), timeout=1)\n'
        'subprocess.run(\n    (\n        runtime,\n        "resident-stop",\n'
        '        "--state-dir",\n        state,\n    ),\n    check=False,\n    timeout=2,\n)\n'
        'run_isolated_hook_process((runtime, "resident-stop"), timeout_seconds=3.0)\n'
        'subprocess.run((runtime, "resident-stop"), timeout=RESIDENT_STOP_TIMEOUT_SECONDS)\n'
    )
    assert _literal_stop_timeouts(source) == [1.0, 2.0, 3.0]


def test_no_harness_gives_resident_stop_less_than_the_runtime_bounds_need() -> None:
    minimum = _minimum_stop_timeout()
    short: list[str] = []
    for directory in ("ci", "scripts"):
        for path in sorted((_ROOT / directory).rglob("*.py")):
            for timeout in _literal_stop_timeouts(path.read_text(encoding="utf-8")):
                if timeout < minimum:
                    short.append(f"{path.relative_to(_ROOT)}: {timeout}")
    assert not short, short
