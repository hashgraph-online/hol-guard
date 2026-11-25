"""Committed project files for live cases that cover earlier false-positive fixes.

Each shape is added only for its own case, after the baseline commit, and
committed the way a cloned project holds it.
"""

from __future__ import annotations

import subprocess
import zlib
from pathlib import Path

# `grep -rln` over a folder of screenshots, one of them full window size.
SCREENS_SEARCH_CASE = "omp-native-grep-recursive-screens-folder-with-capture"
# A project script whose output names passing checks.
REPORT_OUTPUT_CASE = "omp-native-report-script-pass-names-output"
# `grep -rn` over a folder that holds a design tool's own committed dot-folder.
HIDDEN_DESIGN_FOLDER_CASE = "omp-native-grep-recursive-committed-design-dot-folder"
# `cat` of a one-off script kept as a dotfile in a checkout beside the project.
HIDDEN_SCRIPT_CASE = "omp-native-cat-hidden-project-script-in-sibling-checkout"
# The sibling checkout that case reads, below the fixture home.
HIDDEN_SCRIPT_CHECKOUT = ("Code", "acme-platform")

_REPORT_SCRIPT = (
    "import json\n"
    "\n"
    'print(json.dumps({"tests_pass": True, "total": 12}))\n'
    "print(\"both-pass: {'cost': 1.25, 'requests': 14}\")\n"
    'print("all_pass = True")\n'
)


def _png(chunks: list[tuple[bytes, bytes]]) -> bytes:
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    for kind, data in chunks:
        out += len(data).to_bytes(4, "big") + kind + data
        out += zlib.crc32(kind + data).to_bytes(4, "big")
    return bytes(out)


def _capture(pixel_bytes: int) -> bytes:
    """A PNG the size of a full-window screen capture, assembled from one pixel run."""
    return _png(
        [
            (b"IHDR", bytes([0, 0, 11, 72, 0, 0, 7, 128, 8, 6, 0, 0, 0])),
            (b"pHYs", bytes([0, 0, 22, 37, 0, 0, 22, 37, 1])),
            (b"IDAT", bytes(pixel_bytes)),
            (b"IEND", b""),
        ]
    )


def _files(scenario_id: str | None) -> dict[str, bytes]:
    if scenario_id == SCREENS_SEARCH_CASE:
        return {
            "docs/screens/README.md": b"Screens for the login and policy review flows.\n",
            "docs/screens/auth-desktop-login.png": _capture(64),
            # Larger than the whole document budget of a recursive search walk.
            "docs/screens/auth-desktop-policy-review.png": _capture(3 * 1024 * 1024),
        }
    if scenario_id == REPORT_OUTPUT_CASE:
        return {"tools/report.py": _REPORT_SCRIPT.encode()}
    if scenario_id == HIDDEN_DESIGN_FOLDER_CASE:
        return {
            "design/README.md": b"Design notes. The palette lives in the design tool's own file.\n",
            "design/.designtool/design.json": b'{"palette": {"primary": "#1f6feb"}}\n',
        }
    return {}


def _commit(checkout: Path, environment: dict[str, str], files: list[str], *extra: tuple[str, ...]) -> None:
    identity = ("-c", "user.name=Gauntlet Fixture", "-c", "user.email=gauntlet@example.invalid")
    for args in (
        *extra,
        ("add", "--", *files),
        (*identity, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add project files"),
    ):
        subprocess.run(
            ["git", "-C", str(checkout), *args], env=environment, check=True, capture_output=True, timeout=15
        )


def add_hidden_script_checkout(home: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Commit a checkout beside the project that keeps a one-off script as a dotfile."""
    if scenario_id != HIDDEN_SCRIPT_CASE:
        return
    checkout = home.joinpath(*HIDDEN_SCRIPT_CHECKOUT)
    checkout.mkdir(parents=True)
    (checkout / "README.md").write_text("# acme-platform\n", encoding="utf-8", newline="\n")
    (checkout / ".repair-stage.py").write_text("def main():\n    return 0\n", encoding="utf-8", newline="\n")
    _commit(checkout, environment, ["README.md", ".repair-stage.py"], ("init", "--quiet"))


def add_backfill_shapes(workspace: Path, environment: dict[str, str], scenario_id: str | None) -> None:
    """Commit the project files one backfilled case reads."""
    files = _files(scenario_id)
    if not files:
        return
    for relative, data in files.items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    _commit(workspace, environment, list(files))
