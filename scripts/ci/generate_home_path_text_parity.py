"""Record what ``runtime/home_path_text.py`` answers on both platforms.

The module is 23 lines of ``pathlib`` and ``os.path``, so its answers are
whichever flavour of those the running interpreter happens to be. Both
flavours are importable anywhere: ``PurePosixPath``/``posixpath`` give the
POSIX answers and ``PureWindowsPath``/``ntpath`` give the Windows ones, on any
host. The two helpers below are the source's own two functions with those
modules substituted for ``Path`` and ``os.path``, so a case recorded here is
what Guard's Python half would answer on that platform.

Run from the repository root:

    python3 scripts/ci/generate_home_path_text_parity.py
"""

from __future__ import annotations

import json
import ntpath
import posixpath
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

SCHEMA = "home-path-text-parity.v1"
FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/home-path-text-parity.v1.json"

FLAVOURS = {
    "posix": (PurePosixPath, posixpath),
    "windows": (PureWindowsPath, ntpath),
}


def expand_home(value: str, home: str, flavour: str) -> str:
    """``expand_home`` with ``Path`` read as that platform's pure path."""

    pure, _ = FLAVOURS[flavour]
    if value == "~":
        return str(pure(home))
    if value.startswith("~/") or value.startswith("~\\"):
        return str(pure(home) / value[2:])
    return value


def normpath(value: str, flavour: str) -> str:
    """``normalize_path(value, None)`` for a relative or absolute value."""

    _, module = FLAVOURS[flavour]
    return module.normpath(value)


POSIX_HOMES = ("/home/u", "/home/u/", "//srv/share", "///srv/share", "/", ".", "")
POSIX_VALUES = (
    "~",
    "~/",
    "~/.",
    "~/..",
    "~/x",
    "~/a/",
    "~/a//b",
    "~//x",
    "~///x",
    "~/a/./b",
    "~/a/../b",
    "~\\",
    "~\\a",
    "~\\a\\b",
    "~/é/ü",
    "~/ ",
    "plain",
    "~user",
    "/abs/path",
    "",
    "~~",
)

# `splitroot` reads the drive as the first two characters, whatever they
# are, so a drive letter outside ASCII is a drive like any other.
WINDOWS_HOMES = ("C:\\Users\\u", "C:/Users/u", "\\\\srv\\sh", "C:", "C:\\", "é:\\home", "", ".")
WINDOWS_VALUES = (
    "~",
    "~\\",
    "~\\.",
    "~\\..",
    "~\\x",
    "~\\a\\",
    "~\\a\\\\b",
    "~/x",
    "~/a/b",
    "~\\C:y",
    "~\\é:x",
    "~\\é:\\x",
    "~\\c:y",
    "~\\D:y",
    "~\\C:\\z",
    "~\\D:\\q",
    "~\\\\x",
    "~\\\\\\srv\\sh\\f",
    "~\\é\\ü",
    "plain",
    "~user",
    "C:\\abs",
    "",
)

POSIX_NORMPATH = (
    ".",
    "./",
    "./.",
    "a/..",
    "foo/bar/../..",
    "a/../..",
    "..",
    "../..",
    "",
    "/",
    "//",
    "///",
    "//a",
    "///a",
    "/..",
    "/../..",
    "/a//b/./c/../d",
    "a/../b",
    "/a/",
    "a/b/",
    "é/../ü",
    "a/./../b/",
)

WINDOWS_NORMPATH = (
    ".",
    "a\\..",
    "a/..",
    "",
    "C:\\a\\..",
    "C:a\\..",
    "C:\\",
    "C:",
    "\\",
    "\\\\srv\\sh",
    "\\\\srv\\sh\\f\\..",
    "\\\\?\\C:\\z\\..",
    "..\\..",
    "C:\\..",
    "x/y/../z",
    "a\\.\\b\\",
    "é\\..\\ü",
)


def main() -> None:
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "note": (
            "Recorded from pathlib and os.path with the POSIX and Windows "
            "flavours substituted, so both halves are recordable from any "
            "host. Regenerate with "
            "scripts/ci/generate_home_path_text_parity.py."
        ),
    }
    for flavour, homes, values, normpaths in (
        ("posix", POSIX_HOMES, POSIX_VALUES, POSIX_NORMPATH),
        ("windows", WINDOWS_HOMES, WINDOWS_VALUES, WINDOWS_NORMPATH),
    ):
        document[flavour] = {
            "expand_home": [
                {"home": home, "value": value, "expected": expand_home(value, home, flavour)}
                for home in homes
                for value in values
            ],
            "normpath": [
                {"value": value, "expected": normpath(value, flavour)} for value in normpaths
            ],
        }
    FIXTURE.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    for flavour in FLAVOURS:
        section = document[flavour]
        print(
            f"{flavour}: {len(section['expand_home'])} expand_home, "
            f"{len(section['normpath'])} normpath"
        )


if __name__ == "__main__":
    main()
