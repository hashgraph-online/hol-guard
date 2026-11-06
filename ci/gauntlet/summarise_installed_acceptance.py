"""Put the lane's findings in the job summary, not only in an artifact.

A run that reports rather than fails is easy to ignore, and an evidence file
nobody downloads is the same as no evidence. This prints what the lane found
in a shape that reads at a glance from the Actions page.

Run with ``python3 -I`` so nothing is imported from the evidence directory.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def render(path: Path) -> list[str]:
    """One section per evidence file under the given directory."""

    lines: list[str] = ["## Installed acceptance", ""]
    files = sorted(path.glob("*/installed-acceptance.json"))
    if not files:
        lines.append("No evidence was produced: the lane did not get as far as running.")
        return lines
    for file in files:
        evidence = json.loads(file.read_text(encoding="utf-8"))
        runtime = evidence.get("runtime") or {}
        verdict = "accepted" if evidence.get("accepted") else "not accepted"
        lines.append(f"### {file.parent.name} — {verdict}")
        lines.append("")
        lines.append(
            f"`{runtime.get('version', 'unknown')}` as `{runtime.get('kind', 'unknown')}`, "
            f"each replay case run {evidence.get('repeat', '?')} times."
        )
        lines.append("")
        failures = evidence.get("failures") or []
        if not failures:
            lines.append("Nothing to report.")
        for failure in failures:
            lines.append(f"- {failure}")
        lines.append("")
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: summarise_installed_acceptance.py EVIDENCE_DIR", file=sys.stderr)
        return 2
    print("\n".join(render(Path(argv[1]))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
