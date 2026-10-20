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

import glob
import json
import re
import shlex
import shutil
import tempfile
from pathlib import Path

from tests.benign_fp_gate_fixture import build_fixture

_CATALOGUE = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
_TOKEN_PATH = re.compile(r"\$\{[A-Z_]+\}[A-Za-z0-9_./@+*?\[\]-]*")
_GLOB_CHARACTERS = ("*", "?", "[")

# The absence is the shape under test: a probe for a file that is not there,
# or a list of roots where one is missing.
_PROBES_FOR_ABSENCE = frozenset(
    {
        "gauntlet-ls-missing-git-leaf-plain-dir",
        # These two measure the feature worktree's ``node_modules``, and the
        # session they were mined from had one. The fixture cannot give them
        # one yet: three other cases link the main checkout's tree in at that
        # same name, and a link whose destination already exists lands inside
        # it, which is a different command than the one that was observed and
        # is still reviewed. Installing here would turn those three red. The
        # install belongs with the fix for that review, not before it.
        "session-du-sibling-worktree-modules",
        "session-du-sibling-worktree-scripts-sort",
        "observed-ls-lockfile-probe-mixed",
        "queue-grep-head-wc-absent-tmp-trace",
        "session-grep-roots-one-missing-tmp-sibling",
        # A sibling checkout that keeps no workflows, probed for them.
        "sibling-ls-missing-github-workflows",
        "sibling-find-missing-github-workflows",
        "gauntlet-sibling-ls-missing-github-workflows",
        "gauntlet-sibling-find-missing-github-workflows",
    }
)

# Tokens that stand for something other than a path. ``${PORTAL_WEB_HEAD}``
# resolves to a commit id, which a case names where a revision belongs, so
# there is no path for the fixture to build.
_NOT_A_PATH = frozenset({"${PORTAL_WEB_HEAD}"})

# Verbs whose last operand is where the result lands.
_LAST_OPERAND_IS_DESTINATION = frozenset({"cp", "mv", "ln", "install", "rsync"})
# Verbs that create every operand they are given.
_EVERY_OPERAND_IS_CREATED = frozenset({"mkdir", "touch", "tee"})
# Tool inputs that name a file the tool writes, for the tools that write.
_WRITE_TOOL_KEYS = ("file_path", "notebook_path", "path")
_WRITE_TOOLS = ("write", "edit", "notebook")
_SEGMENT_BOUNDARY = re.compile(r"&&|\|\||[;|\n]")


def _operands(words: list[str]) -> list[str]:
    """The words that are not flags, in order."""
    return [word for word in words if not word.startswith("-")]


def _segment_targets(segment: str) -> set[str]:
    """Paths this one command puts something at."""
    targets: set[str] = set()
    for match in re.finditer(r"(?:\d?>>?|&>)\s*(\S+)", segment):
        targets.add(match.group(1))
    try:
        words = shlex.split(segment)
    except ValueError:
        words = segment.split()
    words = [word for word in words if "=" not in word.split("/")[0] or word.startswith("/")]
    if not words:
        return targets
    verb = Path(words[0]).name
    operands = _operands(words[1:])
    if verb in _EVERY_OPERAND_IS_CREATED:
        targets.update(operands)
    elif verb in _LAST_OPERAND_IS_DESTINATION and operands:
        targets.add(operands[-1])
    elif verb == "git":
        # ``git -C <dir>`` reads that directory, so it is not a target; the
        # subcommand's own operand is.
        if "init" in operands:
            targets.update(_first_path(operands[operands.index("init") + 1 :]))
        if "worktree" in operands and "add" in operands:
            targets.update(_first_path(_operands(words[words.index("add") + 1 :])))
    return targets


def _first_path(operands: list[str]) -> list[str]:
    """The first operand that names a path rather than a branch or a flag's value."""
    for operand in operands:
        if "/" in operand or operand.startswith("${"):
            return [operand]
    return []


def _creation_targets(tool_name: str, tool_input: dict[str, object]) -> set[str]:
    """Every path this case's own command or tool input creates."""
    writes = any(verb in tool_name.lower() for verb in _WRITE_TOOLS)
    targets = {
        str(tool_input[key])
        for key in _WRITE_TOOL_KEYS
        if writes and isinstance(tool_input.get(key), str)
    }
    command = tool_input.get("command")
    if isinstance(command, str):
        for segment in _SEGMENT_BOUNDARY.split(command):
            targets.update(_segment_targets(segment))
    return {target.rstrip("/") for target in targets}


def _referenced(tool_name: str, tool_input: dict[str, object]) -> list[str]:
    """Token paths the case names, minus the ones its own command creates."""
    created = _creation_targets(tool_name, tool_input)
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
        if blob[match.end() : match.end() + 1] == "$" and any(
            target.startswith(bare) for target in created
        ):
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
            if case["id"] in _PROBES_FOR_ABSENCE:
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
        try:
            fixture.cleanup()
        except NameError:
            pass
        shutil.rmtree(root, ignore_errors=True)
    assert not missing, (
        "benign cases name paths the fixture does not build, so they measure a "
        "missing path rather than the shape they were written for. Build the "
        "path in tests/benign_fp_gate_fixture.py, or, if the case probes "
        "deliberately for its absence, name the case in this test:\n  "
        + "\n  ".join(missing)
    )
