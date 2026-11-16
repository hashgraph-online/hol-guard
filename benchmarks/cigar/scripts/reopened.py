"""How much of each CIGAR note points at files the agent already opened earlier in the session.

Usage: reopened.py <tag> [<tag> ...]

Probe for E7 (leave out ranges the agent already opened). For each step after the first, counts the
note's mapped ranges and pasted excerpts whose file a tool call named in an earlier step, and the
characters those lines take. File-level: a range in a file the agent opened counts as opened, so this
is an upper bound on what E7 could remove. Reading only.
"""

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anatomy import sessions
from used_notes import touched

LINE = re.compile(r"(?m)^[ \t-]*([\w./-]+\.\w+)(?::\d+[-:]| \(lines \d+-\d+\)).*$")


def main():
    table = Counter()
    for row, steps in sessions(sys.argv[1:]):
        key = row["harness"]
        earlier = []
        for i, (_kind, step) in enumerate(steps):
            for text in step["notes"]:
                text = text.replace("\\n", "\n")
                table[key, "chars"] += len(text)
                if i == 0:
                    continue
                for m in LINE.finditer(text):
                    table[key, "ranges"] += 1
                    if touched(earlier, {m.group(1)}):
                        table[key, "opened"] += 1
                        table[key, "opened_chars"] += len(m.group(0))
            earlier.extend(step["calls"])
    print(f"{'harness':<12} {'ranges':>7} {'opened before':>14} {'chars saved':>12}")
    for harness in sorted({k for k, _ in table}):
        r, o = table[harness, "ranges"], table[harness, "opened"]
        c, oc = table[harness, "chars"], table[harness, "opened_chars"]
        print(f"{harness:<12} {r:>7} {o:>5} {100 * o / max(r, 1):5.1f}% {oc:>6} {100 * oc / max(c, 1):4.1f}%")


if __name__ == "__main__":
    main()
