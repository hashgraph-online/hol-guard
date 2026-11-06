"""Source predicates of the local full-task oracle: real work counts, comments and prose do not."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.full_task_local_checks import (
    _code,
    _game_logic,
    _js_tests_import_source,
    _spawned_script,
    _todo_operations,
    committed_evidence,
)

REST_SERVER = """import { createServer } from 'node:http';
const server = createServer(async (request, response) => {
  if (url.pathname === '/api/todos' && request.method === 'POST') {
    todos.push({ id: crypto.randomUUID(), title, completed: false });
  }
  if (match && request.method === 'PATCH') {
    todo.completed = completed;
  }
  if (match && request.method === 'DELETE') {
    todos.splice(index, 1);
  }
});
server.listen(port, () => console.log(`Todo app running at http://localhost:${port}`));
"""

INLINE_HANDLERS = """export function createTask(text) {
  return { id: `${Date.now()}`, text: text.trim(), completed: false };
}
function render() {
  checkbox.addEventListener('change', () => {
    tasks = tasks.map((entry) => entry.id === task.id ? { ...entry, completed: checkbox.checked } : entry);
  });
  remove.addEventListener('click', () => {
    tasks = tasks.filter((entry) => entry.id !== task.id);
  });
}
document.querySelector('#add-form').addEventListener('submit', (event) => { render(); });
"""

GAME = """export function flap(game) {
  game.velocity = -390;
}
export function update(game, dt) {
  game.velocity += 1250 * dt;
  game.pipes = game.pipes.filter(pipe => pipe.x > -60);
}
"""


def _commit(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    # A private HOME keeps the developer's global Git config and hooks out of the fixture.
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1"}
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.test"]
    for args in (["init", "-q"], ["add", "-A"], [*identity, "commit", "-qm", "init"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, env=env)
    return root


def test_quoted_urls_and_selectors_are_code_but_comments_are_not() -> None:
    code = _code("fetch('http://localhost:3000'); el.querySelector('#list').hidden = true; // gravity\n/* flap */")
    assert "http://localhost:3000" in code and "#list" in code
    assert "gravity" not in code and "flap" not in code
    assert "this.#count" in _code("class A { #count = 0; inc() { this.#count += 1; } }")
    template = _code("const label = `${/* gravity */ count} ${'//kept'}`; // flap\n")
    assert "gravity" not in template and "flap" not in template and "//kept" in template
    python = _code("color = '#fff'  # gravity\n", hash_comments=True)
    assert "#fff" in python and "gravity" not in python


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (GAME, True),
        (GAME.replace("game.velocity += 1250 * dt", "game.vy += GRAVITY * dt"), True),
        # Gravity only in a comment, or no flap at all, is not a game.
        (GAME.replace("game.velocity += 1250 * dt;", "// game.velocity += 1250 * dt;"), False),
        (GAME.replace("flap", "jump"), False),
    ],
)
def test_gravity_may_be_an_accumulating_velocity(source: str, expected: bool) -> None:
    assert _game_logic(_code(source)) is expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (REST_SERVER, True),
        (INLINE_HANDLERS, True),
        # Creating items with an initial state finishes nothing.
        ("export function createTask(text) { return { text, completed: false }; }\n", False),
        (
            "export function createTask(text) { return { text }; }\n"
            "// if (request.method === 'DELETE') todos.splice(i, 1)\n",
            False,
        ),
        ("interface Task { completed: boolean }\nexport function addTask(text) { return { text }; }\n", False),
        (
            "class Todo { constructor(t) { this.completed = false; } }\n"
            "export function addTodo(t) { return new Todo(t); }\n",
            False,
        ),
        # Routes must serve the items; unrelated endpoints are not todo operations.
        ("app.post('/api/todos', add);\napp.delete('/api/todos/:id', drop);\n", True),
        ("analytics.post('/events', send);\nsessions.delete('/sessions', end);\n", False),
    ],
)
def test_todo_operations_include_routes_and_inline_handlers(source: str, expected: bool) -> None:
    assert _todo_operations(_code(source)) is expected


SPAWN = "import { spawn } from 'node:child_process';\n"


@pytest.mark.parametrize(
    ("test_path", "test_source", "expected"),
    [
        ("server.test.js", SPAWN + "test('api', () => { spawn(process.execPath, ['server.js']); });\n", True),
        ("server.test.js", SPAWN + "test('api', () => { exec('node --no-warnings server.js'); });\n", True),
        (
            "server.test.js",
            SPAWN + "test('api', () => { spawn(process.execPath, ['-r', 'dotenv/config', 'server.js']); });\n",
            True,
        ),
        (
            "server.test.js",
            SPAWN + "test('api', () => { exec('node --require ./setup.js server.js'); });\n",
            True,
        ),
        (
            "server.test.js",
            SPAWN + "test('api', () => { exec('node --env-file .env server.js'); });\n",
            True,
        ),
        (
            "server.test.js",
            SPAWN + "test('api', () => { spawn(process.execPath, ['--require', setupPath, 'server.js']); });\n",
            True,
        ),
        (
            "server.test.js",
            SPAWN + "test('api', () => { exec('node --require setup.js', {stdio: 'pipe'}); });\n",
            False,
        ),
        (
            "tests/api.test.js",
            SPAWN + "test('api', () => { spawn(process.execPath, [join(__dirname, '..', 'server.js')]); });\n",
            True,
        ),
        ("server.test.js", SPAWN + "test('api', () => { spawn(process.execPath, ['other.js']); });\n", False),
        # A spawn outside any test case, a commented-out one, or one that evaluates code runs no server.
        ("server.test.js", SPAWN + "spawn(process.execPath, ['server.js']);\n", False),
        ("server.test.js", SPAWN + "test('x', () => {});\n// spawn(process.execPath, ['server.js']);\n", False),
        ("server.test.js", SPAWN + "test('x', () => { spawn(process.execPath, ['-e', 'x', 'server.js']); });\n", False),
    ],
)
def test_tests_may_run_the_committed_server_as_a_child(
    tmp_path: Path, test_path: str, test_source: str, expected: bool
) -> None:
    files = {"server.js": REST_SERVER, test_path: test_source}
    workspace = _commit(tmp_path / "todo", files)
    assert _js_tests_import_source(workspace, sorted(files), _todo_operations) is expected


def test_spawned_script_keeps_option_values_out_of_the_script() -> None:
    assert _spawned_script("process.execPath, ['--require', setupPath, 'server.js']") == "server.js"
    assert _spawned_script("'node --require setup.js', {stdio: 'pipe'}") is None
    assert _spawned_script("process.execPath, ['-e', 'x', 'server.js']") is None


def test_committed_evidence_lists_digests_and_facts_without_contents(tmp_path: Path) -> None:
    test_source = "import { createTask } from '../app.js';\ntest('adds', () => createTask('x'));\n"
    files = {"app.js": INLINE_HANDLERS, "tests/app.test.js": test_source}
    workspace = _commit(tmp_path / "todo", files)
    evidence = committed_evidence(workspace, "todo-app-local")
    assert evidence["committed_files"] == [
        {"path": name, "sha256": hashlib.sha256(files[name].encode()).hexdigest()} for name in sorted(files)
    ]
    assert evidence["files"] == {
        "app.js": {"todo": False, "todo-add": True, "todo-finish": True},
        "tests/app.test.js": {"imports": ["app.js"], "spawns": []},
    }
    assert "createTask" not in str(evidence)
    assert "files" not in committed_evidence(workspace, "python-cli-with-tests")


def test_game_evidence_reads_only_a_pages_scripts(tmp_path: Path) -> None:
    page = "<p>gravity flap pipe</p><canvas></canvas><script>function tick() {}</script>"
    workspace = _commit(tmp_path / "game", {"index.html": page})
    facts = committed_evidence(workspace, "flappy-bird-game")["files"]["index.html"]
    assert facts == {"gravity": False, "flap": False, "pipe": False, "defines-function": True, "loop": False}
