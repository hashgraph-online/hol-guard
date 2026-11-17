"""Used-note and wrong-note rates from finished runs' transcripts.

Usage: used_notes.py <tag> [<tag> ...]

For every step whose CIGAR note named project files (a mapped range `path:12-30`, a pasted excerpt
`path (lines 1-112)` or an "Other matching files" list), looks at the agent's tool calls in that
step. The note was used when a call names one of its files; wrong when the agent worked on other
project files and none of the note's; neither when the agent named no project file at all (a
question it answered from the note, or a step done without files). Reading only.
"""

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anatomy import sessions

EXT = r"(?:py|rs|go|ts|js|md|toml|cfg|txt|rst|ini|json|yml|yaml)"
NAMED = re.compile(rf"([\w./-]+\.{EXT})(?::\d+(?:-\d+)?| \(lines \d+)")
OTHERS = re.compile(r"Other matching files: ([^\n]+)")
# A project file a call names: any path with a folder, or a root-level file with a note extension.
FILE = re.compile(rf"[\w.-]+/[\w./-]+\.\w+|(?<![\w./-])[\w-]+\.{EXT}\b")
TOKEN = re.compile(r"[\w.-]+(?:/[\w.-]+)*")


def note_files(notes):
    files = set()
    for text in notes:
        text = text.replace("\\n", "\n")  # Claude Code attachments are stored JSON-escaped
        files.update(NAMED.findall(text))
        for line in OTHERS.findall(text):
            files.update(part.strip(" .`") for part in line.split(","))
    return {f for f in files if f}


def same_file(token, path):
    """A call's path token names the note's file: equal, or one is the other with a leading folder
    (`./src/a.py`, an absolute path, or a bare `a.py` run from that folder). A different file that
    shares part of the name (`test_a.py`) does not match."""
    token, path = token.removeprefix("./"), path.removeprefix("./")
    return token == path or token.endswith("/" + path) or path.endswith("/" + token)


def touched(calls, files):
    return any(same_file(token, f) for call in calls for token in TOKEN.findall(call) for f in files)


def main():
    table = Counter()
    for row, steps in sessions(sys.argv[1:]):
        for _kind, step in steps:
            files = note_files(step["notes"])
            if not files:
                continue
            key = (row["harness"], row["arm"])
            table[key, "notes"] += 1
            if touched(step["calls"], files):
                table[key, "used"] += 1
            elif any(FILE.search(call) for call in step["calls"]):
                table[key, "wrong"] += 1
            else:
                table[key, "neither"] += 1

    print(f"{'harness':<12} {'arm':<10} {'notes':>5} {'used':>12} {'wrong':>12} {'neither':>12}")
    for harness, arm in sorted({k for k, _ in table}):
        n = table[(harness, arm), "notes"]
        cells = " ".join(f"{table[(harness, arm), c]:>4} {100 * table[(harness, arm), c] / n:5.1f}%"
                         for c in ("used", "wrong", "neither"))
        print(f"{harness:<12} {arm:<10} {n:>5} {cells}")


if __name__ == "__main__":
    main()
