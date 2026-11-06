"""Benign source search fixture (T640).

This fixture simulates a legitimate source code search operation.
No secret files are read. No external network calls are made.
All identifiers are benign.
"""

import os
import re

_SEARCH_ROOT = "src"
_PATTERN = re.compile(r"def\s+\w+\(")


def search_functions(root: str) -> list[tuple[str, int, str]]:
    matches: list[tuple[str, int, str]] = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath) as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if _PATTERN.search(line):
                            matches.append((fpath, lineno, line.rstrip()))
            except OSError:
                pass
    return matches


if __name__ == "__main__":
    for path, line, text in search_functions(_SEARCH_ROOT):
        print(f"{path}:{line}: {text}")
