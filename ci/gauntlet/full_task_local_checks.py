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

from .full_task_git import blob, git_lines, tree

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
_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*|(?m:#[^\n]*$)", re.S)


def _code(text: str) -> str:
    """Lowercased source with line and block comments removed, so a comment is not proof of behavior."""
    return _COMMENTS.sub(" ", text).lower()


def _defines(text: str, words: tuple[str, ...]) -> bool:
    """The code defines a function or method whose name contains one of ``words``."""
    names = "|".join(words)
    return bool(
        re.search(rf"\b(?:def|function|func|fn|fun)\s+[\w$]*(?:{names})[\w$]*\s*\(", text)
        or re.search(rf"[\w$]*(?:{names})[\w$]*\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)", text)
        or re.search(rf"^\s*(?:async\s+|static\s+)*[\w$]*(?:{names})[\w$]*\s*\([^)]*\)\s*\{{", text, re.M)
    )


def _todo_operations(text: str) -> bool:
    """Code that defines both an add-like and a finish-like operation."""
    return _defines(text, TODO_ADD) and _defines(text, TODO_FINISH)


def _game_logic(text: str) -> bool:
    """Code that names gravity, flapping and pipes and defines a function."""
    return all(word in text for word in ("gravity", "flap", "pipe")) and _defines(text, ("",))


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
            if modules & imported and accept(_code(source_text)):
                return text, True
    return text, False


def _js_tests_import_source(
    workspace: Path, files: list[str], accept: Callable[[str], bool] = lambda _text: True
) -> bool:
    """A committed JS test imports a committed non-test module, by a relative path, whose code ``accept`` approves."""
    committed = set(files)
    sources = {name for name in files if name.endswith(JS_SUFFIXES) and not _JS_TEST.search(name)}
    for test in (name for name in files if name.endswith(JS_SUFFIXES) and _JS_TEST.search(name)):
        text = blob(workspace, "HEAD", test)
        if not re.search(r"\b(test|it)\s*\(", text):
            continue
        for target in _JS_IMPORT.findall(text):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(test), target))
            candidates = {resolved, *(resolved + suffix for suffix in JS_SUFFIXES), resolved + "/index.js"}
            for source in candidates & sources & committed:
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
    text = "\n".join(blob(workspace, "HEAD", name) for name in sources if not name.endswith(".py")).lower()
    text += "\n" + python_text
    return {
        "task:committed-app-source": "todo" in text and _todo_operations(_code(text)),
        "task:committed-tests": python_tests or _js_tests_import_source(workspace, files, _todo_operations),
        "task:tests-pass": _ran_python_tests(workspace, home) or _ran_node_tests(workspace, home),
        "task:committed-clean": clean,
    }


LOCAL_APP_CHECKS = {"flappy-bird-game": flappy_bird_checks, "todo-app-local": todo_local_checks}
