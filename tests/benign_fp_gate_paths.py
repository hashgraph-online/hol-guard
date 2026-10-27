"""Materialise the fixture paths that benign gate cases name.

The mined cases name project directories (scrubbed to stand-in names) that the
hand-built fixture never grew. Instead of listing them one by one, derive them
from the cases: every ``${HOME}``, ``${PRIVATE_TMP}`` and ``${WORKTREE}`` path in
a case that expects ``allow`` is created, so a listing or a search has something
to read and the case measures its labelled class rather than a missing path.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from collections.abc import Iterator
from pathlib import Path

CASES_PATH = Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json"
ROOT_TOKENS = ("HOME", "PRIVATE_TMP", "WORKTREE")
# A path ends at whitespace, a quote, a shell operator or a glob character.
_PATH_TOKEN = re.compile(r"\$\{(" + "|".join(ROOT_TOKENS) + r")\}((?:/(?:[^\s'\"`;&|<>()*?$\[\]{}\\]|\$(?![{(]))+)*)")
_CREDENTIAL_NAME = re.compile(
    r"(^\.env(\..*)?$|^id_|\.pem$|\.key$|\.p12$|\.pfx$|credential|secret|token|^auth\.json$|^\.netrc$|^\.npmrc$)",
    re.IGNORECASE,
)
_KNOWN_FILES = frozenset({"Makefile", "Dockerfile", "LICENSE", "README", "Procfile", "Gemfile", "Justfile"})
_CODE_PARENTS = frozenset({"src", "lib", "scripts", "tools", "__tests__", "tests", "workers"})


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
            targets.update(_first_path(_worktree_add_operands(words[words.index("add") + 1 :])))
    return targets


# ``git worktree add`` flags whose value is the next word. A branch name holds
# a slash as often as a path does, so a flag's value has to be dropped before
# the destination can be picked out of the operands.
_WORKTREE_ADD_FLAGS_TAKING_A_VALUE = frozenset({"-b", "-B", "--reason"})


def _worktree_add_operands(words: list[str]) -> list[str]:
    """The operands of ``git worktree add``, without flags or their values."""
    operands: list[str] = []
    skip_value = False
    for word in words:
        if skip_value:
            skip_value = False
            continue
        if word in _WORKTREE_ADD_FLAGS_TAKING_A_VALUE:
            skip_value = True
            continue
        if word.startswith("-"):
            continue
        operands.append(word)
    return operands


def _first_path(operands: list[str]) -> list[str]:
    """The first operand that names a path rather than a branch or a flag's value."""
    for operand in operands:
        if "/" in operand or operand.startswith("${"):
            return [operand]
    return []


def creation_targets(tool_name: str, tool_input: dict[str, object]) -> set[str]:
    """Every path this case's own command or tool input creates."""
    writes = any(verb in tool_name.lower() for verb in _WRITE_TOOLS)
    targets = {str(tool_input[key]) for key in _WRITE_TOOL_KEYS if writes and isinstance(tool_input.get(key), str)}
    command = tool_input.get("command")
    if isinstance(command, str):
        for segment in _SEGMENT_BOUNDARY.split(command):
            targets.update(_segment_targets(segment))
    return {target.rstrip("/") for target in targets}


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def is_credential_like(relative: str) -> bool:
    return any(_CREDENTIAL_NAME.search(part) for part in relative.split("/") if part)


def is_file_like(relative: str) -> bool:
    name = posixpath.basename(relative)
    if name in _KNOWN_FILES or (name.endswith("rc") and name.startswith(".")):
        return True
    # A package manager's shim directory holds executables, never folders. A
    # path that names the directory itself, with or without a trailing slash,
    # is still a directory.
    if name and {"bin", ".bin"} & set(relative.split("/")[:-1]):
        return True
    # `.deploy.lock.d` is a lock directory; a bare dotfile such as `.audit-trail` is a directory.
    stem = name.lstrip(".")
    return bool(posixpath.splitext(stem)[1]) and not name.endswith(".d")


# The absence is the shape under test: a probe for a file that is not there,
# or a list of roots where one is missing.
PROBES_FOR_ABSENCE = frozenset(
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
        # A scratch directory under the temporary root, probed for an
        # optional dependency tree and a stale temp directory. The listing
        # prints only an error, which is the whole shape.
        "gauntlet-ls-stage-missing-modules",
        "gauntlet-ls-stage-missing-hidden-tmp",
        "gauntlet-ls-stage-missing-hidden-leaf",
        "observed-ls-06",
        # A sibling checkout that keeps no workflows, probed for them.
        "sibling-ls-missing-github-workflows",
        "sibling-find-missing-github-workflows",
        "gauntlet-sibling-ls-missing-github-workflows",
        "gauntlet-sibling-find-missing-github-workflows",
        # A `-C` route to a directory that was never cloned: the whole point
        # of the case is that Git prints the path it could not enter.
        "observed-git-18",
        "gauntlet-git-C-missing-checkout-log",
        # A read of a name that is not in the worktree: the absence is the
        # whole case, since an absent name under the workspace is what the
        # missing-read screen admits without a review.
        "cat-missing-name-inside-the-worktree",
        # A recursive read whose root is not there: the walk opens nothing,
        # which is exactly the shape these cases measure. Building the root
        # would turn them into ordinary recursive reads of a populated tree,
        # which other cases already cover.
        "grep-recursive-absent-sibling-dir",
        "grep-recursive-absent-nested-module",
        "ls-recursive-absent-sibling-dir",
        "ls-recursive-absent-nested-module",
        "tree-recursive-absent-sibling-dir",
        "tree-recursive-absent-nested-module",
        "grep-recursive-absent-probe-fallback",
        "ls-recursive-absent-probe-fallback",
    }
)


def benign_path_tokens(document: dict[str, object] | None = None) -> set[tuple[str, str]]:
    """``(root token, relative path)`` pairs named by cases that expect ``allow``."""
    cases = (document or json.loads(CASES_PATH.read_text(encoding="utf-8")))["cases"]
    found: set[tuple[str, str]] = set()
    created: set[tuple[str, str]] = set()
    for case in cases:
        if case.get("expect") != "allow":
            continue
        for target in creation_targets(case.get("tool", ""), case.get("tool_input", {})):
            for match in _PATH_TOKEN.finditer(target):
                created.add((match.group(1), posixpath.normpath("/" + match.group(2).strip("/")).strip("/")))
        if case.get("id") in PROBES_FOR_ABSENCE:
            # The case was mined from a session where the path was not there,
            # and the absence is what it measures. Building it would turn the
            # probe into an ordinary read of a populated tree.
            continue
        for text in _strings(case.get("tool_input", {})):
            for match in _PATH_TOKEN.finditer(text):
                relative = posixpath.normpath("/" + match.group(2).strip("/")).strip("/")
                partial = text[match.end() : match.end() + 1] in {"*", "?", "[", "{", "."}
                if partial:
                    # A glob or brace continues the last name, so only its parent is a real path.
                    relative = posixpath.dirname(relative)
                if relative and ".git" not in relative.split("/"):
                    found.add((match.group(1), relative))
    # A path some case's own command creates must stay absent, or that case
    # measures a destination that already exists rather than the one observed.
    return {
        (token, relative)
        for token, relative in found
        if not any(
            token == made_token and (relative == made or relative.startswith(made + "/"))
            for made_token, made in created
        )
    }


def materialise(roots: dict[str, Path], document: dict[str, object] | None = None) -> list[tuple[str, str]]:
    """Create each benign path under its root. Returns the credential-like paths left alone."""
    skipped: list[tuple[str, str]] = []
    directories: list[Path] = []
    for token, relative in sorted(benign_path_tokens(document)):
        if is_credential_like(relative):
            skipped.append((token, relative))
            continue
        target = roots[token] / relative
        if target.exists():
            continue
        if any(parent.is_file() for parent in target.parents if roots[token] in parent.parents):
            continue
        if is_file_like(relative):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"# {target.name}\nSynthetic placeholder content.\n", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
            directories.append(target)
    for directory in directories:
        if any(directory.iterdir()):
            continue
        if directory.name.endswith(".d"):
            (directory / "pid").write_text("4242\n", encoding="utf-8")
        elif directory.name in _CODE_PARENTS:
            (directory / "index.ts").write_text("export const placeholder = 1;\n", encoding="utf-8")
        else:
            (directory / "README.md").write_text(
                f"# {directory.name}\nSynthetic placeholder notes.\n", encoding="utf-8"
            )
    return skipped


def missing_paths(roots: dict[str, Path], document: dict[str, object] | None = None) -> list[str]:
    """Benign, non-credential paths the built fixture does not contain."""
    return sorted(
        f"${{{token}}}/{relative}"
        for token, relative in benign_path_tokens(document)
        if not is_credential_like(relative) and not (roots[token] / relative).exists()
    )
