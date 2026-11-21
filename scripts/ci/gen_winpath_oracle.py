"""Generate the CPython 3.12 oracle for the Rust Windows path model.

Run with CPython 3.12 (``ntpath`` and ``pathlib.PureWindowsPath`` behave the same
on every host)::

    python scripts/ci/gen_winpath_oracle.py > \
        rust/crates/guard-command/tests/fixtures/winpath_oracle.v1.json
"""

from __future__ import annotations

import json
import ntpath
import sys
from pathlib import PureWindowsPath as P

PATHS = [
    "",
    ".",
    "a",
    "a\\b",
    "a/b/",
    "a//b/./c",
    "..",
    "..\\a",
    "a\\..\\b",
    "C:",
    "C:\\",
    "C:/",
    "c:\\Users\\x",
    "C:\\Users\\x\\",
    "C:Users",
    "C:..\\x",
    "\\",
    "\\x",
    "\\\\",
    "\\\\server\\share",
    "\\\\server\\share\\",
    "\\\\server\\share\\a\\b",
    "//server/share/a",
    "\\\\?\\C:\\a",
    "\\\\?\\UNC\\srv\\sh\\x",
    "\\\\.\\dev",
    "\\\\.\\dev\\x",
    "C:\\a\\.\\b\\..\\c",
    "C:\\..\\a",
    "C:\\a b\\c d",
    "x:y\\z",
    "a:b",
    "C:\\Temp\\",
    "D:\\a",
    "\\\\srv",
    "\\\\srv\\",
]
CHILDS = [
    "",
    "b",
    "b\\c",
    "..",
    "\\r",
    "/r",
    "D:\\x",
    "D:x",
    "c:x",
    "C:\\y",
    "C:y",
    "\\\\h\\s\\z",
    ".",
    "x/./y",
    "C:",
    "C:\\",
]


def rows() -> list[list[str]]:
    out: list[list[str]] = []
    for path in PATHS:
        win = P(path)
        out.append(["str", path, str(win)])
        out.append(["name", path, win.name])
        out.append(["parent", path, str(win.parent)])
        out.append(["abs", path, "1" if win.is_absolute() else "0"])
        out.append(["normpath", path, ntpath.normpath(path)])
        head, tail = ntpath.split(path)
        out.append(["split", path, head + "\x00" + tail])
    for path in PATHS:
        for child in CHILDS:
            out.append(["join", path + "\x00" + child, str(P(path) / child)])
            out.append(["ntjoin", path + "\x00" + child, ntpath.join(path, child)])
    return out


if __name__ == "__main__":
    json.dump({"schema": "guard-winpath-oracle.v1", "python": sys.version.split()[0], "cases": rows()}, sys.stdout)
    sys.stdout.write("\n")
