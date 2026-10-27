"""Every path a benign case reads has to be in the gate fixture.

The catalogue names its paths through tokens (``${HOME}``, ``${ORG_WT}``,
``${PRIVATE_TMP}``), and the tokens resolve whether or not anything is there.
A case whose path is missing still runs and can still pass, but it measures
*Guard was asked about a path that is not there* rather than the shape the
case was written for, and a screen that canonicalises its target cannot tell
those two apart. Mined cases are scrubbed of private names before they are
added, so this is the easy mistake to make: the rename lands in the catalogue
and nothing creates the renamed directory.

So a benign case must find its paths in the fixture, unless the command itself
is what puts something there. Which path that is comes out of the command: the
operand a ``mkdir``, ``touch``, ``git init`` or ``git worktree add`` names, the
destination of a copy, move or link, a redirect target, the file a write tool
is handed. Every other path a case names is read, and has to be there, so the
exemption covers a copy's destination without covering its source. A handful
of cases probe deliberately for something absent and name themselves below.
"""

from __future__ import annotations

import contextlib
import glob
import json
import re
import shutil
import tempfile
from pathlib import Path

from tests.benign_fp_gate_fixture import build_fixture
from tests.benign_fp_gate_paths import (
    PROBES_FOR_ABSENCE,
    ROOT_TOKENS,
    benign_path_tokens,
    creation_targets,
    is_credential_like,
    is_file_like,
    missing_paths,
)

_CATALOGUE = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
_TOKEN_PATH = re.compile(r"\$\{[A-Z_]+\}[A-Za-z0-9_./@+*?\[\]-]*")
_GLOB_CHARACTERS = ("*", "?", "[")

# Tokens that stand for something other than a path. ``${PORTAL_WEB_HEAD}``
# resolves to a commit id, which a case names where a revision belongs, so
# there is no path for the fixture to build.
_NOT_A_PATH = frozenset({"${PORTAL_WEB_HEAD}"})


def _referenced(tool_name: str, tool_input: dict[str, object]) -> list[str]:
    """Token paths the case names, minus the ones its own command creates."""
    created = creation_targets(tool_name, tool_input)
    blob = json.dumps(tool_input)
    named = []
    for match in _TOKEN_PATH.finditer(blob):
        reference = match.group()
        bare = reference.rstrip("/")
        if bare in created:
            continue
        # A path whose own name holds a ``$`` — a dynamic route file such as
        # ``posts.$postId.tsx`` — ends the token match early, so the created
        # path it belongs to only starts with what was matched.
        if blob[match.end() : match.end() + 1] == "$" and any(target.startswith(bare) for target in created):
            continue
        named.append(reference)
    return named


def test_every_benign_case_finds_the_paths_it_reads() -> None:
    catalogue = json.loads(_CATALOGUE.read_text())
    root = Path(tempfile.mkdtemp(prefix="gate-fixture-paths-"))
    try:
        fixture = build_fixture(root)
        tokens = fixture.tokens()
        missing: list[str] = []
        for case in catalogue["cases"] + catalogue.get("mcp_cases", []):
            if case.get("expect") != "allow":
                continue
            if case["id"] in PROBES_FOR_ABSENCE:
                continue
            for reference in _referenced(case.get("tool", ""), case.get("tool_input", {})):
                token = reference[: reference.index("}") + 1]
                if token not in tokens or token in _NOT_A_PATH:
                    continue
                resolved = reference.replace(token, tokens[token]).rstrip("/")
                path = Path(resolved)
                if path.exists() or path.is_symlink():
                    # Brackets are a path of their own in a dynamic route
                    # directory such as ``app/registry/[slug]``, so the literal
                    # name is tried before the pattern.
                    continue
                if any(character in resolved for character in _GLOB_CHARACTERS):
                    # A pattern names a set of paths, and the case was mined
                    # from a session where it matched something.
                    if not glob.glob(resolved):
                        missing.append(f"{case['id']}: {reference} (matched nothing)")
                    continue
                missing.append(f"{case['id']}: {reference}")
    finally:
        with contextlib.suppress(NameError):
            fixture.cleanup()
        shutil.rmtree(root, ignore_errors=True)
    assert not missing, (
        "benign cases name paths the fixture does not build, so they measure a "
        "missing path rather than the shape they were written for. Build the "
        "path in tests/benign_fp_gate_fixture.py, or, if the case probes "
        "deliberately for its absence, name the case in this test:\n  " + "\n  ".join(missing)
    )


def test_every_benign_case_path_exists_in_the_built_fixture(tmp_path: Path) -> None:
    fixture = build_fixture(tmp_path)
    try:
        roots = {"HOME": fixture.home, "PRIVATE_TMP": fixture.private_tmp, "WORKTREE": fixture.worktree}
        assert missing_paths(roots) == []
        # The mined stand-in projects are among the paths the derivation found.
        named = {relative for _token, relative in benign_path_tokens()}
        assert {"audit-trail/__tests__", "signup-funnel", "audit-trail/tools/usage-rollup"} <= named
        assert (fixture.worktree / "signup-funnel").is_dir()
        assert any((fixture.private_tmp / "audit-trail" / "src").iterdir())
    finally:
        fixture.cleanup()


def test_credential_like_paths_are_never_materialised() -> None:
    for relative in (
        ".codex/auth.json",
        ".ssh/id_rsa",
        "app/.env",
        ".env.local",
        "k/server.pem",
        ".claude/.credentials.json",
    ):
        assert is_credential_like(relative), relative
    for relative in ("audit-trail/src", ".claude/settings.json", ".codex/plans/todo.md"):
        assert not is_credential_like(relative), relative


def test_file_and_directory_shapes() -> None:
    assert is_file_like("a/notes.md") and is_file_like("a/Makefile") and is_file_like(".claude/settings.json")
    assert (
        not is_file_like("signup-funnel") and not is_file_like("a/.deploy.lock.d") and not is_file_like(".audit-trail")
    )
    # A package manager writes executable shims into `node_modules/.bin`, so a
    # case naming one must meet a file there, not a placeholder directory.
    assert is_file_like("node_modules/.bin/vitest") and is_file_like("app/node_modules/.bin/vite")
    assert not is_file_like("node_modules/.bin") and not is_file_like("app/node_modules/.bin/")


def test_a_probe_for_an_absent_path_is_never_built() -> None:
    """The fixture leaves the path an absence probe names alone.

    ``benign_path_tokens`` derives the fixture's paths from the cases, so
    without this exclusion it would build ``${HOME}/not-cloned-yet`` and the
    other names these cases exist to find missing, and each probe would
    measure an ordinary read of a populated tree instead.
    """
    catalogue = json.loads(_CATALOGUE.read_text())
    probes = [case for case in catalogue["cases"] if case["id"] in PROBES_FOR_ABSENCE]
    assert probes, "the catalogue holds no absence probes, so this pin measures nothing"
    built = benign_path_tokens(catalogue)
    named: set[tuple[str, str]] = set()
    for case in probes:
        for reference in _referenced(case.get("tool", ""), case.get("tool_input", {})):
            token = reference[: reference.index("}") + 1]
            if token not in {f"${{{root}}}" for root in ROOT_TOKENS}:
                continue
            named.add((token.strip("${}"), reference[len(token) :].strip("/")))
    # A path another case also names is still built for that case; only the
    # ones no other case asks for disappear.
    others = {case["id"] for case in catalogue["cases"]} - PROBES_FOR_ABSENCE
    kept = benign_path_tokens({"cases": [case for case in catalogue["cases"] if case["id"] in others]})
    assert named - kept, "no absence probe names a path of its own, so this pin measures nothing"
    assert (named - kept) & built == set()
