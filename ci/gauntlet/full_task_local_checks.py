"""Physical checks for local full tasks that build a small app with tests and commit it.

The model picks the language and layout, so these checks read what Git holds: committed
sources, committed tests that import one of them, a test run that passed with at least one
test, and a clean tree with at least one commit. Status is read before any test runs,
because test runners leave caches behind.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import subprocess
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from .full_task_git import blob, blob_sha256, git_lines, tree

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx")
APP_SUFFIXES = (*JS_SUFFIXES, ".html", ".py", ".vue", ".svelte")
_JS_TEST = re.compile(r"(^|/)(tests?|__tests__)/|\.(test|spec)\.[cm]?[jt]sx?$")
_JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)['"](\.{1,2}/[^'"]+)['"]""", re.M)
# Passing-count lines from node --test (TAP and spec reporters), Jest, Vitest and Mocha.
_JS_PASSED = (
    re.compile(r"^\s*(?:#|\u2139)\s*pass\s+([1-9]\d*)", re.M),
    re.compile(r"\bTests?:?\s+([1-9]\d*)\s+passed", re.M),
    re.compile(r"^\s*([1-9]\d*)\s+passing\b", re.M),
)
_NPM_PLACEHOLDER = "no test specified"
# Untracked output of running or installing the project, not part of what the agent was asked to commit.
GENERATED = frozenset({"__pycache__", ".pytest_cache", "node_modules", ".DS_Store"})
TODO_ADD = ("add", "create", "new")
TODO_FINISH = ("done", "complete", "toggle", "remove", "delete")
# Operations written inline rather than as named functions: a REST route, an event handler that
# creates, completes or drops an item. They read lowercased code with comments already removed.
# A route registered by path must name the items it serves; ``analytics.post('/events')`` is no todo.
_ITEM_ROUTE = r"""\s*\(\s*['"`]/[^'"`]*(?:todo|task|item|:id)"""
_TODO_ADD_CODE = re.compile(rf"""\bmethod\s*===?\s*['"]post['"]|\.post{_ITEM_ROUTE}""")
_TODO_FINISH_CODE = re.compile(
    rf"""\bmethod\s*===?\s*['"](?:patch|put|delete)['"]|\.(?:patch|put|delete){_ITEM_ROUTE}"""
    r"""|\.(?:completed|done)\s*=(?!=)(?!\s*false\b)|\b(?:completed|done)\s*:\s*(?!(?:false|boolean|bool)\b)[\w$!]"""
    r"""|\.splice\s*\(|\.filter\s*\(\s*\(?\s*([\w$]+)\s*\)?\s*=>\s*\1\.id\s*!=="""
)
# Gravity is named, or is a velocity that accumulates every step, as in ``bird.velocity += 1250 * dt``.
_GRAVITY = re.compile(r"gravity|\b(?:[\w$]*velocity[\w$]*|vel[xy]?|vy|dy)\s*\+=")
# Node child-process calls; the script such a call runs is exercised by the test.
_JS_SPAWN = re.compile(r"\b(?:spawn|spawnSync|fork|exec|execSync|execFile|execFileSync)\s*\(([^;]{0,400})")
_JS_LITERAL = re.compile(r"""(['"`])([^'"`]*)\1""")
# ``join(__dirname, '..', 'server.js')`` or ``path.resolve('src', 'server.js')`` built from literals.
_JS_JOINED = re.compile(
    r"""\b(?:join|resolve)\s*\(\s*(?:[\w$.]+\s*,\s*)?((?:['"`][^'"`]*['"`]\s*,\s*)*['"`][^'"`]*['"`])(?:\s*,)?\s*\)"""
)
_NODE_EVAL = frozenset({"-e", "--eval", "-p", "--print"})
# Node options whose next word is a value, not the script. ``--require=./setup.js``
# stays a flag because it already starts with ``-``.
_NODE_VALUED = frozenset(
    {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--env-file",
        "-C",
        "--conditions",
    }
)
_LAUNCHERS = frozenset({"node", "nodejs"})


def _uncommented(text: str, hash_comments: bool = False) -> str:
    """Source with comments removed, so a comment is not proof of behavior.

    Quoted text is kept, so ``'http://localhost'`` or ``'#list'`` is not mistaken for a comment;
    code inside a template's ``${...}`` is still code. ``#`` starts a comment only for Python and
    shell (``hash_comments``); in JavaScript it is a selector, a private field or part of a string.
    Single and double quotes end at a newline, so a stray apostrophe in markup cannot hide more
    than its own line.
    """
    out: list[str] = []
    index, size, quote = 0, len(text), ""
    # Brace depth of each open template interpolation, innermost last.
    templates: list[int] = []
    while index < size:
        char = text[index]
        if quote:
            if char == "\\" and index + 1 < size:
                out.append(text[index : index + 2])
                index += 2
                continue
            if quote == "`" and text.startswith("${", index):
                templates.append(0)
                quote = ""
                out.append("${")
                index += 2
                continue
            if char == quote or (char == "\n" and quote != "`"):
                quote = ""
            out.append(char)
            index += 1
        elif templates and char in "{}":
            if char == "}" and templates[-1] == 0:
                templates.pop()
                quote = "`"
            else:
                templates[-1] += 1 if char == "{" else -1
            out.append(char)
            index += 1
        elif char in "'\"`":
            quote = char
            out.append(char)
            index += 1
        elif (hash_comments and char == "#") or (not hash_comments and text.startswith("//", index)):
            end = text.find("\n", index)
            index = size if end < 0 else end
            out.append(" ")
        elif not hash_comments and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = size if end < 0 else end + 2
            out.append(" ")
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _code(text: str, hash_comments: bool = False) -> str:
    """Lowercased source with comments removed; see ``_uncommented``."""
    return _uncommented(text, hash_comments).lower()


def _scan_js_string(source: str, index: int) -> tuple[str, int]:
    """The contents of a quote starting at ``index``, and the index after the closer."""

    quote = source[index]
    index += 1
    chars: list[str] = []
    size = len(source)
    while index < size:
        char = source[index]
        if char == "\\" and index + 1 < size:
            chars.append(source[index + 1])
            index += 2
            continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    return "".join(chars), index


def _scan_js_array(source: str, index: int) -> tuple[list[str | None], int]:
    """Array elements from ``[``. A non-literal element is ``None``."""

    index += 1
    slots: list[str | None] = []
    size = len(source)
    while index < size:
        while index < size and source[index] in " \t\r\n,":
            index += 1
        if index >= size or source[index] == "]":
            return slots, index + 1 if index < size else index
        if source[index] in "'\"`":
            text, index = _scan_js_string(source, index)
            slots.append(text)
            continue
        depth = 0
        start = index
        while index < size:
            char = source[index]
            if char in "'\"`":
                _, index = _scan_js_string(source, index)
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif char == "," and depth == 0:
                break
            index += 1
        if index == start:
            index += 1
        slots.append(None)
    return slots, index


def _call_argument_slots(source: str) -> list[str | None]:
    """Node argv slots for a child-process call.

    A command string contributes its words as one slot. An args array contributes one slot per
    element, with ``None`` where the element is not a literal. An options object is not argv.
    """

    slots: list[str | None] = []
    index, size, saw_array = 0, len(source), False
    while index < size:
        while index < size and source[index] in " \t\r\n":
            index += 1
        if index >= size or source[index] in "{);}":
            break
        if source[index] == "[":
            elements, index = _scan_js_array(source, index)
            saw_array = True
            slots.extend(elements)
        elif source[index] in "'\"`" and not saw_array:
            text, index = _scan_js_string(source, index)
            slots.append(text)
        else:
            depth = 0
            start = index
            while index < size:
                char = source[index]
                if char in "'\"`":
                    _, index = _scan_js_string(source, index)
                    continue
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif char == "," and depth == 0:
                    break
                index += 1
            if index == start:
                index += 1
        while index < size and source[index] in " \t\r\n":
            index += 1
        if index < size and source[index] == ",":
            index += 1
    return slots


def _script_from_slots(slots: list[str | None]) -> str | None:
    """The script in ``slots``. A valued option consumes the next word or the next slot."""

    skip_value = False
    for slot in slots:
        if slot is None:
            if skip_value:
                skip_value = False
                continue
            return None
        for word in slot.split():
            if skip_value:
                skip_value = False
                continue
            if word in _NODE_EVAL:
                return None
            if word in _NODE_VALUED:
                skip_value = True
                continue
            if word not in _LAUNCHERS and not word.startswith("-"):
                return word
    return None


def _spawned_script(arguments: str) -> str | None:
    """The script a child-process call runs.

    The first argv word that is neither the Node launcher nor a flag. The value after an option
    such as ``--require`` or ``--env-file`` is not the script, including when that value is a
    variable. Literals in a later options object are not argv. Code passed with ``-e``/``-p``
    runs no script.
    """

    arguments = _JS_JOINED.sub(
        lambda match: "'" + posixpath.join(*(part for _, part in _JS_LITERAL.findall(match.group(1)))) + "'",
        arguments,
    )
    return _script_from_slots(_call_argument_slots(arguments))


def _defines(text: str, words: tuple[str, ...]) -> bool:
    """The code defines a function or method whose name contains one of ``words``."""
    names = "|".join(words)
    return bool(
        re.search(rf"\b(?:def|function|func|fn|fun)\s+[\w$]*(?:{names})[\w$]*\s*\(", text)
        or re.search(rf"[\w$]*(?:{names})[\w$]*\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)", text)
        or re.search(rf"^\s*(?:async\s+|static\s+)*[\w$]*(?:{names})[\w$]*\s*\([^)]*\)\s*\{{", text, re.M)
    )


def _todo_add(text: str) -> bool:
    return _defines(text, TODO_ADD) or _TODO_ADD_CODE.search(text) is not None


def _todo_finish(text: str) -> bool:
    return _defines(text, TODO_FINISH) or _TODO_FINISH_CODE.search(text) is not None


def _todo_operations(text: str) -> bool:
    """Code that adds an item and completes or removes one, by named function, handler or route."""
    return _todo_add(text) and _todo_finish(text)


def _game_facts(text: str) -> dict[str, bool]:
    return {
        "gravity": _GRAVITY.search(text) is not None,
        "flap": "flap" in text,
        "pipe": "pipe" in text,
        "defines-function": _defines(text, ("",)),
    }


def _game_logic(text: str) -> bool:
    """Code with gravity, flapping and pipes that defines a function."""
    return all(_game_facts(text).values())


class _InlineScripts(HTMLParser):
    """Collects the text of ``<script>`` elements that carry no ``src`` attribute."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self._open: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script" and not any(name == "src" for name, _ in attrs):
            self._open = []

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._open.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._open is not None:
            self.scripts.append("".join(self._open))
            self._open = None


def inline_scripts(html: str) -> list[str]:
    """Inline script bodies of an HTML document, tolerant of ``</script >`` and any tag case."""
    parser = _InlineScripts()
    parser.feed(html)
    parser.close()
    return parser.scripts


def _parses_as_js(text: str, home: Path) -> bool:
    """Node accepts the script as an ES module or as CommonJS."""
    for flags in (["--input-type=module"], ["--input-type=commonjs"]):
        try:
            result = subprocess.run(
                ["node", *flags, "--check", "-"],
                input=text,
                env={"PATH": os.environ.get("PATH", ""), "HOME": str(home)},
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode == 0:
            return True
    return False


def _output(command: list[str], cwd: Path, home: Path) -> str | None:
    """Combined output of a bounded command in the disposable fixture; None unless it exited 0."""
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "NO_COLOR": "1", "CI": "1"}
    try:
        result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout + result.stderr if result.returncode == 0 else None


def _passes(command: list[str], cwd: Path, home: Path) -> bool:
    return _output(command, cwd, home) is not None


def _ran_python_tests(workspace: Path, home: Path) -> bool:
    """The project's Python tests passed and at least one ran."""
    unittest = _output(["python3", "-m", "unittest", "discover", "-s", ".", "-v"], workspace, home)
    if unittest and (ran := re.search(r"Ran (\d+) tests?", unittest)) and int(ran.group(1)) > 0:
        return True
    pytest = _output(["python3", "-m", "pytest", "-q"], workspace, home)
    return bool(pytest and re.search(r"\b[1-9]\d* passed", pytest))


def _ran_node_tests(workspace: Path, home: Path) -> bool:
    """The package's test script, or ``node --test``, passed and reported at least one passing test."""
    commands = []
    try:
        script = json.loads((workspace / "package.json").read_text(encoding="utf-8")).get("scripts", {}).get("test")
    except (OSError, ValueError, AttributeError):
        script = None
    if isinstance(script, str) and script.strip() and _NPM_PLACEHOLDER not in script:
        commands.append(["npm", "test", "--silent"])
    commands.append(["node", "--test"])
    for command in commands:
        output = _output(command, workspace, home)
        if output and any(pattern.search(output) for pattern in _JS_PASSED):
            return True
    return False


def _python_test(name: str) -> bool:
    """A pytest- or unittest-discoverable test file: ``test*.py`` or ``*_test.py``."""
    base = Path(name)
    return name.endswith(".py") and (base.name.startswith("test") or base.stem.endswith("_test"))


def python_test_evidence(
    workspace: Path, files: list[str], accept: Callable[[str], bool] = lambda _text: True
) -> tuple[str, bool]:
    """Committed non-test Python source text, and whether one committed test file both defines tests and
    imports a committed source module whose code ``accept`` approves.

    Imports count with dotted paths such as ``tempconv.core`` or ``src.tempconv``. Each test file
    must carry both the tests and the import; evidence split across files does not count.
    """
    sources = {
        name: blob(workspace, "HEAD", name).lower() for name in files if name.endswith(".py") and not _python_test(name)
    }
    text = "\n".join(sources.values())
    for name in (name for name in files if _python_test(name)):
        test_text = blob(workspace, "HEAD", name).lower()
        if not ("def test" in test_text or "testcase" in test_text):
            continue
        imported = {
            segment
            for statement in re.findall(r"^\s*(?:from\s+([\w.]+)|import\s+([\w., ]+))", test_text, re.MULTILINE)
            for path in "".join(statement).split(",")
            for segment in path.split(" as ")[0].strip().split(".")
        }
        for source, source_text in sources.items():
            modules = {part.lower() for part in Path(source).with_suffix("").parts if part != "__init__"}
            if modules & imported and accept(_code(source_text, hash_comments=True)):
                return text, True
    return text, False


def _js_test_targets(test: str, text: str, sources: set[str]) -> dict[str, list[str]]:
    """Committed sources a JS test imports by relative path, or runs as a child process by path.

    A spawned script is resolved against the test's directory and the repository root, where the
    test runner starts. A test that defines no ``test``/``it`` case reaches nothing, and commented
    out code reaches nothing.
    """
    found: dict[str, list[str]] = {"imports": [], "spawns": []}
    text = _uncommented(text)
    if not re.search(r"\b(test|it)\s*\(", text):
        return found
    for target in _JS_IMPORT.findall(text):
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(test), target))
        candidates = {resolved, *(resolved + suffix for suffix in JS_SUFFIXES), resolved + "/index.js"}
        found["imports"].extend(sorted(candidates & sources))
    for arguments in _JS_SPAWN.findall(text):
        if target := _spawned_script(arguments):
            bases = (posixpath.dirname(test), "")
            candidates = {posixpath.normpath(posixpath.join(base, target)) for base in bases}
            found["spawns"].extend(sorted(candidates & sources))
    return found


def _js_tests_import_source(
    workspace: Path, files: list[str], accept: Callable[[str], bool] = lambda _text: True
) -> bool:
    """A committed JS test imports, or runs by path, a committed non-test module whose code ``accept`` approves."""
    sources = {name for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)}
    for test in (name for name in files if name.endswith(JS_SUFFIXES) and _JS_TEST.search(name)):
        targets = _js_test_targets(test, blob(workspace, "HEAD", test), sources)
        for source in {*targets["imports"], *targets["spawns"]}:
            if accept(_code(blob(workspace, "HEAD", source))):
                return True
    return False


def committed_clean(workspace: Path) -> bool:
    """At least one commit, and nothing modified or untracked except generated caches and installs."""
    if not git_lines(workspace, "rev-list", "HEAD"):
        return False
    for line in git_lines(workspace, "status", "--porcelain"):
        parts = line[3:].strip('"').rstrip("/").split("/")
        if not (line.startswith("?? ") and (set(parts) & GENERATED or parts[-1].endswith(".pyc"))):
            return False
    return True


def flappy_bird_checks(workspace: Path, home: Path) -> dict[str, bool]:
    """A committed canvas game with gravity, flapping and pipes, and committed passing JS tests."""
    clean = committed_clean(workspace)
    files = tree(workspace, "HEAD")
    pages = "\n".join(blob(workspace, "HEAD", name) for name in files if name.endswith((".html", ".htm")))
    scripts = "\n".join(
        blob(workspace, "HEAD", name) for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)
    )
    game = (pages + "\n" + scripts).lower()
    inline = inline_scripts(pages)
    plain = [
        blob(workspace, "HEAD", name)
        for name in files
        if name.endswith((".js", ".mjs", ".cjs")) and not _JS_TEST.search(name)
    ]
    # TypeScript and JSX need a compiler Node does not ship; their text is judged without a parse.
    typed = [
        blob(workspace, "HEAD", name)
        for name in files
        if name.endswith((".ts", ".tsx", ".jsx")) and not _JS_TEST.search(name)
    ]
    parsed = [text for text in plain + inline if _parses_as_js(text, home)] + typed
    code = _code("\n".join(parsed))
    loop = re.search(r"requestanimationframe\s*\(|setinterval\s*\(", code) is not None
    return {
        "task:committed-html-canvas": bool(pages)
        and ("<canvas" in pages.lower() or "createelement('canvas')" in game or 'createelement("canvas")' in game),
        "task:committed-game-loop": loop and _game_logic(code),
        "task:committed-tests": _js_tests_import_source(workspace, files, _game_logic),
        "task:tests-pass": _ran_node_tests(workspace, home),
        "task:committed-clean": clean,
    }


def todo_local_checks(workspace: Path, home: Path) -> dict[str, bool]:
    """A committed todo app in any common language, with committed passing tests that import it."""
    clean = committed_clean(workspace)
    files = tree(workspace, "HEAD")
    python_text, python_tests = python_test_evidence(workspace, files, _todo_operations)
    sources = [name for name in files if name.endswith(APP_SUFFIXES) and not _JS_TEST.search(name)]
    script = "\n".join(blob(workspace, "HEAD", name) for name in sources if not name.endswith(".py"))
    text = script.lower() + "\n" + python_text
    code = _code(script) + "\n" + _code(python_text, hash_comments=True)
    return {
        "task:committed-app-source": "todo" in text and _todo_operations(code),
        "task:committed-tests": python_tests or _js_tests_import_source(workspace, files, _todo_operations),
        "task:tests-pass": _ran_python_tests(workspace, home) or _ran_node_tests(workspace, home),
        "task:committed-clean": clean,
    }


def committed_evidence(workspace: Path, task_id: str) -> dict[str, Any]:
    """What the checks read, without file contents, so a failed case can be diagnosed later.

    Every committed file is listed by path and SHA-256. For the local app tasks each committed
    source also carries the facts its predicates use, and each JS test the committed sources it
    imports or runs.
    """
    files = tree(workspace, "HEAD")
    evidence: dict[str, Any] = {
        "committed_files": [{"path": name, "sha256": blob_sha256(workspace, "HEAD", name)} for name in files]
    }
    if task_id not in LOCAL_APP_CHECKS:
        return evidence
    sources = {name for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)}
    facts: dict[str, dict[str, Any]] = {}
    for name in (name for name in files if name.endswith(APP_SUFFIXES)):
        raw = blob(workspace, "HEAD", name)
        if name.endswith(JS_SUFFIXES) and _JS_TEST.search(name):
            facts[name] = _js_test_targets(name, raw, sources)
            continue
        code = _code(raw, hash_comments=name.endswith(".py"))
        if task_id == "flappy-bird-game":
            # Page prose is not game logic; only a page's inline scripts are.
            if name.endswith(".html"):
                code = _code("\n".join(inline_scripts(raw)))
            loop = re.search(r"requestanimationframe\s*\(|setinterval\s*\(", code) is not None
            facts[name] = {**_game_facts(code), "loop": loop}
        else:
            todo = "todo" in raw.lower()
            facts[name] = {"todo": todo, "todo-add": _todo_add(code), "todo-finish": _todo_finish(code)}
    evidence["files"] = facts
    return evidence


LOCAL_APP_CHECKS = {"flappy-bird-game": flappy_bird_checks, "todo-app-local": todo_local_checks}
