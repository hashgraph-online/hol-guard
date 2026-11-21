"""How much of each CIGAR note points at files the agent already opened earlier in the session.

Usage: reopened.py <tag> [<tag> ...]

Probe: would leaving out ranges the agent already opened save much? For each step after the first, counts the
note's mapped ranges and pasted excerpts whose file a tool call named in an earlier step, and the
characters those lines take. File-level: a range in a file the agent opened counts as opened, so this
is an upper bound on what leaving them out could remove. A pasted excerpt counts with its whole code block, not
just its header line. The last column weighs those characters (about four to a token) by the
requests that carry them (every request from that step to the session's end) against the session's
input tokens, so it is the share of input leaving them out could save. Reading only.
"""

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anatomy import sessions
from used_notes import touched

LINE = re.compile(r"(?m)^[ \t-]*([\w./-]+\.\w+)(?::\d+[-:]| \(lines \d+-\d+\)).*$")
FENCE = re.compile(r"\n```[^\n]*\n.*?\n```", re.S)


def span(text, m):
    """A range line, plus the fenced code block that follows it when it heads a pasted excerpt."""
    block = FENCE.match(text, m.end())
    return block.end() - m.start() if block else len(m.group(0))


def main():
    table = Counter()
    for row, steps in sessions(sys.argv[1:]):
        key = row["harness"]
        earlier = []
        table[key, "input"] += row["tokens"].get("input_tokens", 0)
        for i, (_kind, step) in enumerate(steps):
            later = sum(s["requests"] for _k, s in steps[i:])
            for text in step["notes"]:
                text = text.replace("\\n", "\n")
                table[key, "chars"] += len(text)
                if i == 0:
                    continue
                for m in LINE.finditer(text):
                    table[key, "ranges"] += 1
                    if touched(earlier, {m.group(1)}):
                        table[key, "opened"] += 1
                        chars = span(text, m)
                        table[key, "opened_chars"] += chars
                        table[key, "carried"] += chars / 4 * later
            earlier.extend(step["calls"])
    print(f"{'harness':<12} {'ranges':>7} {'opened before':>14} {'chars saved':>12} {'input':>6}")
    for harness in sorted({k for k, _ in table}):
        r, o = table[harness, "ranges"], table[harness, "opened"]
        c, oc = table[harness, "chars"], table[harness, "opened_chars"]
        share = 100 * table[harness, "carried"] / max(table[harness, "input"], 1)
        print(f"{harness:<12} {r:>7} {o:>5} {100 * o / max(r, 1):5.1f}% {oc:>6} {100 * oc / max(c, 1):4.1f}% "
              f"{share:5.1f}%")


if __name__ == "__main__":
    main()
