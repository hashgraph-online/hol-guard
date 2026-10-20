"""A session opened in a plain folder beside the checkout it edits.

Agents are often started in a folder that is not a repository, such as the one
above or next to their clones, and change the checkout through absolute paths.
A file-edit call, a shell redirect, an append, a quoted heredoc and a staged
copy followed by a write are the same ordinary edit a session inside the
repository makes, so none of them is held for review. The session folder only
exists for the Oh My Pi runner, which starts the agent there; harness lanes that
cannot choose a working directory run the same cases from the project.
"""

from __future__ import annotations

from pathlib import Path

SESSION_FOLDER = "work"
# The fixture's existing sibling repository stands in for a fresh clone.
CHECKOUT = "other-project"
EDIT_CASE = "omp-native-edit-clone-beside-session-folder"
SHELL_CASE = "omp-native-shell-writes-clone-beside-session-folder"
CASES = frozenset({EDIT_CASE, SHELL_CASE})

REPORT_BEFORE = "report-window-marker"
REPORT_AFTER = "report-window-fixed"
STAGED_FILES = {
    "x.ts": "export const summary = 2;\n",
    "a.ts": "export const copied = 3;\n",
}
PENDING_NOTE = "# Pending\n- retry window\n"


def session_cwd(home: Path, workspace: Path, scenario_id: str) -> Path:
    """The folder the agent starts in: a plain directory for these cases, the project otherwise."""
    return home / SESSION_FOLDER if scenario_id in CASES else workspace


def seed_session_folder(home: Path, stage: Path, scenario_id: str) -> None:
    """Create the plain session folder and, for the shell case, the staged source files."""
    if scenario_id not in CASES:
        return
    (home / SESSION_FOLDER).mkdir(mode=0o700, exist_ok=True)
    if scenario_id != SHELL_CASE:
        return
    stage.mkdir(mode=0o700, parents=True)
    for name, text in STAGED_FILES.items():
        (stage / name).write_text(text, encoding="utf-8", newline="\n")


def _exact(path: Path, expected: str) -> bool:
    """A readable regular file holding exactly the expected text."""
    try:
        return path.is_file() and not path.is_symlink() and path.read_bytes() == expected.encode("utf-8")
    except OSError:
        return False


def session_folder_checks(home: Path, scenario_id: str) -> dict[str, bool]:
    """Bytes the checkout must hold after the case, read from disk and never from the model's account."""
    checkout = home / CHECKOUT
    if scenario_id == EDIT_CASE:
        expected = f"export const reportWindow = '{REPORT_AFTER}';\n"
        return {"session-folder-edit-exact": _exact(checkout / "src/report.ts", expected)}
    if scenario_id != SHELL_CASE:
        return {}
    staged = STAGED_FILES
    try:
        report = (checkout / "src/report.ts").read_bytes()
    except OSError:
        report = b""
    original = f"export const reportWindow = '{REPORT_BEFORE}';\n".encode("utf-8")
    appended = report == original + staged["x.ts"].encode("utf-8")
    return {
        "session-folder-shell-exact": all(
            (
                _exact(checkout / "src/summary.ts", staged["x.ts"]),
                appended,
                _exact(checkout / ".pending-edits.md", PENDING_NOTE),
                _exact(checkout / "src/copied.ts", staged["a.ts"]),
            )
        )
    }
