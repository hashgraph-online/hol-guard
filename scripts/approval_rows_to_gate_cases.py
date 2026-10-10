"""Turn redacted approval-queue rows into model-free benign false-positive gate cases.

Input is a JSON array (or JSON lines) of rows with ``harness``, ``tool_name``, ``tool_input`` (or
``command``) and ``reason_code``. Output is a JSON array of gate case entries for
``tests/fixtures/benign_false_positive_gate.json``. Absolute user paths, home directories, private
owner and repository names are replaced with the generic gate tokens and ``o/r`` before anything is
written, so a case built from a real queue row is safe to commit to a public repository.

Usage: python scripts/approval_rows_to_gate_cases.py rows.json [--owner NAME ...] > cases.json
Review the result before merging: this tool does not decide that a row was benign.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SHELL_TOOLS = {"bash", "shell", "Bash", "exec_command"}
FAMILY = {"read": "read", "Read": "read", "glob": "glob", "Glob": "glob", "grep": "grep", "Grep": "grep"}
FAMILY |= {"write": "write", "Write": "write", "eval": "eval", "task": "task", "wait": "wait"}
FAMILY |= {"todo": "todo", "todo_write": "todo_write", "ls": "ls"}
_HOME = re.compile(r"(?:/Users|/home)/[^/\s'\"]+|C:\\Users\\[^\\\s'\"]+")
# Any non-hidden folder under home is treated as a project checkout.
_PROJECT = re.compile(r"\$\{HOME\}/[A-Za-z][^/\s'\"]*/[^\s'\"]+")
_TEMP = re.compile(r"(?:/private)?/tmp/[A-Za-z0-9._-]+")


def scrub(text: str, owners: list[str]) -> str:
    """Replace identifying path and name fragments with generic fixture values."""
    text = _HOME.sub("${HOME}", text)
    text = _PROJECT.sub("${WORKTREE}", text)
    text = _TEMP.sub("${PRIVATE_TMP}", text)
    for owner in owners:
        text = re.sub(re.escape(owner) + r"/[A-Za-z0-9._-]+", "o/r", text, flags=re.IGNORECASE)
        text = re.sub(re.escape(owner), "o", text, flags=re.IGNORECASE)
    return text


def scrub_value(value: Any, owners: list[str]) -> Any:
    if isinstance(value, str):
        return scrub(value, owners)
    if isinstance(value, list):
        return [scrub_value(item, owners) for item in value]
    if isinstance(value, dict):
        return {key: scrub_value(item, owners) for key, item in value.items()}
    return value


def load_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [row for row in data if isinstance(row, dict)]


def to_case(row: dict[str, Any], owners: list[str]) -> dict[str, Any] | None:
    tool = str(row.get("tool_name") or "")
    tool_input = row.get("tool_input")
    if tool in SHELL_TOOLS:
        command = row.get("command") or (tool_input or {}).get("command" if isinstance(tool_input, dict) else "")
        if not isinstance(command, str) or not command:
            return None
        kind, payload = "shell", {"command": command}
    elif tool in FAMILY and isinstance(tool_input, dict):
        kind, payload = FAMILY[tool], dict(tool_input)
        if "file_path" in payload and "path" not in payload:
            payload["path"] = payload.pop("file_path")
    else:
        return None
    payload = scrub_value(payload, owners)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:8]
    harness = str(row.get("harness") or "omp")
    is_git = kind == "shell" and re.match(r"\s*git\b", payload["command"]) is not None
    return {
        "id": f"observed-{kind}-{digest}",
        "fix_area": "git" if is_git else ("omp" if harness == "omp" and kind != "shell" else kind),
        "harnesses": [harness],
        "tool": kind,
        "tool_input": payload,
        "cwd": "worktree",
        "expect": "allow",
        "observed_reason_code": str(row.get("reason_code") or ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("rows", type=Path)
    parser.add_argument("--owner", action="append", default=[], help="private owner name to replace with o")
    args = parser.parse_args()
    cases: dict[str, dict[str, Any]] = {}
    for row in load_rows(args.rows):
        case = to_case(row, args.owner)
        if case is not None:
            cases.setdefault(case["id"], case)
    json.dump(sorted(cases.values(), key=lambda c: c["id"]), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
