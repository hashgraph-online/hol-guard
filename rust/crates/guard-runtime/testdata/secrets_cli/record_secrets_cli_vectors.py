"""Record HOL Guard Secrets parity vectors from the Python implementation.

The Python package was removed when the native runtime took over, so run
this from a checkout that still has it (for example commit 55e051a711),
with that checkout's environment:

    python record_secrets_cli_vectors.py <repo-root> <output.json>

Two vector families:

* ``text``: every ``scan_secret_text`` call made by the Python detection and
  precision test modules, with the public summary it returned.
* ``cli``: a fixture directory built from declarative steps, one request in
  the shape the CLI sends to the native runtime, and the Python response
  (public result or error text). Hook cases also record the hooks directory.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_TOKEN = "<ROOT>"
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Guard Test",
    "GIT_AUTHOR_EMAIL": "guard@example.invalid",
    "GIT_COMMITTER_NAME": "Guard Test",
    "GIT_COMMITTER_EMAIL": "guard@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}
# Inherited repository-location variables (set when running inside a Git
# hook) override `git -C`, so fixture commands would touch the caller's repo.
GIT_LOCATION_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_COMMON_DIR",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)
TEXT_TEST_MODULES = (
    "tests/test_guard_secret_detection.py",
    "tests/test_guard_secret_fixture_precision.py",
    "tests/test_guard_secret_assignment_precision.py",
)


def _p(*parts: str) -> str:
    # Split literals keep scanners and push protection from flagging fixtures.
    return "".join(parts)


GITHUB = _p("gh", "p_", "Ab3dEf5hIj7lMn9pQr2tUv4xYz6Bcd8Fgh1Jkl3N")
AWS = _p("AK", "IA", "Z7QW4E2R9T1Y6U3I")
STRIPE = _p("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dcAb9X")
PEM = _p(
    "-----BEGIN ",
    "OPENSSH PRIVATE KEY-----\n",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n",
    "-----END ",
    "OPENSSH PRIVATE KEY-----\n",
)
DB_URL = _p("postgres://app:", "Xk29vQp7LmN4rT8w", "@db.internal:5432/app")
ASSIGN = _p("PAYMENTS_API_SECRET=", "q8Vz2Lm4Np7Rt1Wx9Ky3Hb6Jd5Fg0Sc")
MISSING_BLOB = "0123456789abcdef0123456789abcdef01234567"

# Direct `scan_secret_text` calls beyond the test modules: the fixture-marker
# context window is three lines either side (Python `splitlines()` slicing),
# and only `str.isdigit()` characters count as a digit class.
EXTRA_TEXT_CASES: list[tuple[str, dict[str, object]]] = [
    (f"it('loads', () => {{\n  const token = '{GITHUB}'\n", {"path": "tests/fixtures/client.ts"}),
    (f"it('loads', () => {{\n\n\n\n  const token = '{GITHUB}'\n", {"path": "tests/fixtures/client.ts"}),
    (f"it('loads', () => {{\r\n\r\n\r\n\r\n  const token = '{GITHUB}'\n", {"path": "tests/fixtures/client.ts"}),
    (f"it('loads', () => {{\u2028\u2028\u2028\u2028  const token = '{GITHUB}'\n", {"path": "tests/fixtures/client.ts"}),
    (f"it('loads', () => {{\r\r\r\r  const token = '{GITHUB}'\n", {"path": "tests/fixtures/client.ts"}),
    (f"const token = '{GITHUB}'\n\n\n\nexpect(token)\n", {"path": "tests/fixtures/client.ts"}),
    ("TOKEN=aaabcdefABCDEFGHIJK\u2167\n", {"path": "src/config.py"}),
    ("TOKEN=aaabcdefABCDEFGHIJK\u00b2\n", {"path": "src/config.py"}),
    ("TOKEN=aaabcdefABCDEFGHIJK\u0663\n", {"path": "src/config.py"}),
]


def _write(path: str, text: str) -> dict[str, object]:
    return {"op": "write", "path": path, "text": text}


def _git(*args: str) -> dict[str, object]:
    return {"op": "git", "args": list(args)}


INIT = [_git("init", "-q", "-b", "main")]


def _commit(message: str) -> dict[str, object]:
    return _git("commit", "-q", "--no-verify", "-m", message)


def _scan(scope: str = "working", target: str = ".", **bounds: int) -> dict[str, object]:
    request: dict[str, object] = {"command": "scan", "target": target, "scope": scope}
    request.update(bounds)
    return request


def _hook(command: str, target: str = ".") -> dict[str, object]:
    return {"command": command, "target": target}


CLI_CASES: list[dict[str, object]] = [
    {"name": "empty_directory", "setup": [], "request": _scan()},
    {"name": "clean_repository", "setup": [*INIT, _write("README.md", "hello\n")], "request": _scan()},
    {
        "name": "working_tree_provider_tokens",
        "setup": [
            _write("src/config.py", f"GITHUB_TOKEN={GITHUB}\nAWS_ACCESS_KEY_ID={AWS}\n"),
            _write("billing/stripe.env", f"STRIPE_KEY={STRIPE}\n"),
            _write("keys/id_ed25519", PEM),
            _write("app/settings.py", f"DATABASE_URL={DB_URL}\n{ASSIGN}\n"),
            _write("docs/example.md", "token = YOUR_TOKEN_HERE\n"),
        ],
        "request": _scan(),
    },
    {
        "name": "binary_file_skipped",
        "setup": [
            {
                "op": "write_b64",
                "path": "bin/blob.bin",
                "data": base64.b64encode(b"\x00\x01" + GITHUB.encode() + b"\x00").decode(),
            },
            _write("ok.txt", "nothing here\n"),
        ],
        "request": _scan(),
    },
    {
        "name": "max_findings_truncates",
        "setup": [_write(f"f{i}.env", f"GITHUB_TOKEN={GITHUB}\n") for i in range(4)],
        "request": _scan(max_findings=2),
    },
    {
        "name": "max_files_truncates",
        "setup": [_write(f"f{i}.env", f"GITHUB_TOKEN={GITHUB}\n") for i in range(4)],
        "request": _scan(max_files=1),
    },
    {
        "name": "max_file_bytes_skips_large_file",
        "setup": [_write("big.env", "x" * 300 + f"\nGITHUB_TOKEN={GITHUB}\n"), _write("small.env", f"T={AWS}\n")],
        "request": _scan(max_file_bytes=64),
    },
    {
        "name": "max_total_bytes_truncates",
        "setup": [_write(f"f{i}.env", f"GITHUB_TOKEN={GITHUB}\n") for i in range(3)],
        "request": _scan(max_total_bytes=70),
    },
    {"name": "missing_target", "setup": [], "request": _scan(target="missing")},
    {
        "name": "single_file_target",
        "setup": [_write("one.env", f"GITHUB_TOKEN={GITHUB}\n")],
        "request": _scan(target="one.env"),
    },
    {"name": "history_on_non_git_target", "setup": [_write("a.txt", "x\n")], "request": _scan("history")},
    {
        "name": "history_finds_removed_secret",
        "setup": [
            *INIT,
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
            _git("add", "config.env"),
            _commit("add config"),
            _write("config.env", "GITHUB_TOKEN=\n"),
            _git("add", "config.env"),
            _commit("remove token"),
        ],
        "request": _scan("history"),
    },
    {
        "name": "history_bounded_to_one_commit",
        "setup": [
            *INIT,
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
            _git("add", "config.env"),
            _commit("add config"),
            _write("config.env", "GITHUB_TOKEN=\n"),
            _git("add", "config.env"),
            _commit("remove token"),
        ],
        "request": _scan("history", max_commits=1),
    },
    {
        "name": "history_with_deleted_file_and_rename",
        "setup": [
            *INIT,
            _write("a.env", f"AWS={AWS}\n"),
            _write("b.env", "safe\n"),
            _git("add", "."),
            _commit("one"),
            _git("mv", "b.env", "c.env"),
            _git("rm", "-q", "a.env"),
            _commit("two"),
        ],
        "request": _scan("history"),
    },
    {
        "name": "staged_reads_index_not_worktree",
        "setup": [
            *INIT,
            _write("config.env", "SAFE_VALUE=hello\n"),
            _git("add", "config.env"),
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
        ],
        "request": _scan("staged"),
    },
    {
        "name": "staged_secret",
        "setup": [
            *INIT,
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
            _write("other.env", f"AWS={AWS}\n"),
            _git("add", "."),
        ],
        "request": _scan("staged"),
    },
    {
        "name": "staged_after_commit_and_deletion",
        "setup": [
            *INIT,
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
            _git("add", "."),
            _commit("one"),
            _git("rm", "-q", "config.env"),
            _write("new.env", f"STRIPE={STRIPE}\n"),
            _git("add", "new.env"),
        ],
        "request": _scan("staged"),
    },
    {
        "name": "staged_bounded_findings",
        "setup": [*INIT, *[_write(f"f{i}.env", f"GITHUB_TOKEN={GITHUB}\n") for i in range(3)], _git("add", ".")],
        "request": _scan("staged", max_findings=1),
    },
    {"name": "staged_on_non_git_directory", "setup": [_write("a.txt", "x\n")], "request": _scan("staged")},
    {"name": "staged_on_missing_target", "setup": [], "request": _scan("staged", target="missing")},
    {"name": "install_hook_fresh", "setup": [*INIT], "request": _hook("install-hook"), "hooks": True},
    {
        "name": "install_hook_chains_user_hook",
        "setup": [
            *INIT,
            _write(".git/hooks/pre-commit", "#!/bin/sh\necho user-hook\n"),
            {"op": "chmod_x", "path": ".git/hooks/pre-commit"},
        ],
        "request": _hook("install-hook"),
        "hooks": True,
    },
    {
        "name": "install_hook_twice_is_idempotent",
        "setup": [*INIT, {"op": "request", "request": _hook("install-hook")}],
        "request": _hook("install-hook"),
        "hooks": True,
    },
    {
        "name": "uninstall_restores_user_hook",
        "setup": [
            *INIT,
            _write(".git/hooks/pre-commit", "#!/bin/sh\necho user-hook\n"),
            {"op": "chmod_x", "path": ".git/hooks/pre-commit"},
            {"op": "request", "request": _hook("install-hook")},
        ],
        "request": _hook("uninstall-hook"),
        "hooks": True,
    },
    {
        "name": "uninstall_managed_only",
        "setup": [*INIT, {"op": "request", "request": _hook("install-hook")}],
        "request": _hook("uninstall-hook"),
        "hooks": True,
    },
    {"name": "uninstall_when_absent", "setup": [*INIT], "request": _hook("uninstall-hook"), "hooks": True},
    {
        "name": "uninstall_leaves_foreign_hook",
        "setup": [*INIT, _write(".git/hooks/pre-commit", "#!/bin/sh\necho mine\n")],
        "request": _hook("uninstall-hook"),
        "hooks": True,
    },
    {"name": "install_hook_non_git", "setup": [], "request": _hook("install-hook")},
    {"name": "install_hook_missing_target", "setup": [], "request": _hook("install-hook", target="missing")},
    {
        "name": "install_hook_refuses_custom_hooks_path",
        "setup": [*INIT, _git("config", "core.hooksPath", ".githooks")],
        "request": _hook("install-hook"),
    },
    {
        "name": "install_hook_refuses_existing_backup",
        "setup": [
            *INIT,
            _write(".git/hooks/pre-commit", "#!/bin/sh\necho user-hook\n"),
            _write(".git/hooks/pre-commit.hol-guard-user", "#!/bin/sh\necho old\n"),
        ],
        "request": _hook("install-hook"),
        "hooks": True,
    },
    {
        "name": "install_hook_refuses_symlinked_hook",
        "setup": [
            *INIT,
            _write("elsewhere.sh", "#!/bin/sh\n"),
            {"op": "symlink", "path": ".git/hooks/pre-commit", "to": "../../elsewhere.sh"},
        ],
        "request": _hook("install-hook"),
        "hooks": True,
    },
    {
        "name": "uninstall_refuses_symlinked_hook",
        "setup": [
            *INIT,
            _write("elsewhere.sh", "#!/bin/sh\n"),
            {"op": "symlink", "path": ".git/hooks/pre-commit", "to": "../../elsewhere.sh"},
        ],
        "request": _hook("uninstall-hook"),
        "hooks": True,
    },
    {
        "name": "staged_blob_oversized",
        "setup": [*INIT, _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"), _git("add", "config.env")],
        "request": _scan("staged", max_file_bytes=8),
    },
    {
        "name": "staged_blob_unavailable",
        "setup": [
            *INIT,
            _write("config.env", f"GITHUB_TOKEN={GITHUB}\n"),
            _git("add", "config.env"),
            _git("update-index", "--add", "--cacheinfo", f"100644,{MISSING_BLOB},ghost.env"),
        ],
        "request": _scan("staged"),
    },
    {
        "name": "uninstall_restores_backup_when_hook_missing",
        "setup": [*INIT, _write(".git/hooks/pre-commit.hol-guard-user", "#!/bin/sh\necho mine\n")],
        "request": _hook("uninstall-hook"),
        "hooks": True,
    },
]


def _normalize(value: object, root: str) -> object:
    if isinstance(value, str):
        return value.replace(root, ROOT_TOKEN)
    if isinstance(value, list):
        return [_normalize(item, root) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item, root) for key, item in value.items()}
    return value


def _run_request(request: dict[str, object], root: Path) -> dict[str, object]:
    from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook, uninstall_precommit_hook
    from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
    from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets

    target = root / str(request["target"])
    bounds = {
        key: request[key]
        for key in ("max_files", "max_file_bytes", "max_total_bytes", "max_findings")
        if key in request
    }
    try:
        command = request["command"]
        if command == "scan":
            scope = request["scope"]
            if scope == "staged":
                result = scan_staged_secrets(target, **bounds)
            else:
                if "max_commits" in request:
                    bounds["max_commits"] = request["max_commits"]
                result = scan_repository_secrets(target, include_history=scope == "history", **bounds)
        elif command == "install-hook":
            result = install_precommit_hook(target)
        else:
            result = uninstall_precommit_hook(target)
    except (OSError, ValueError) as error:
        return {"ok": False, "error": str(error)}
    return {"ok": True, "result": result.to_public_dict()}


def _apply(step: dict[str, object], root: Path) -> None:
    op = step["op"]
    if op == "git":
        subprocess.run(["git", "-C", str(root), *step["args"]], check=True, capture_output=True)
        return
    if op == "request":
        _run_request(step["request"], root)
        return
    path = root / str(step["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    if op == "write":
        path.write_text(str(step["text"]), encoding="utf-8")
    elif op == "write_b64":
        path.write_bytes(base64.b64decode(str(step["data"])))
    elif op == "chmod_x":
        path.chmod(0o755)
    elif op == "symlink":
        path.symlink_to(str(step["to"]))
    else:
        raise ValueError(op)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _encoded(step: dict[str, object]) -> dict[str, object]:
    # Fixture credentials are stored base64-encoded so the vector file never
    # holds a literal token pattern.
    if step["op"] == "write":
        return {"op": "write_b64", "path": step["path"], "data": _b64(str(step["text"]))}
    return step


def _hooks_state(root: Path) -> dict[str, object]:
    hooks = root / ".git" / "hooks"
    state: dict[str, object] = {}
    for entry in sorted(hooks.iterdir()) if hooks.is_dir() else ():
        if entry.name.endswith(".sample"):
            continue
        if entry.is_symlink():
            state[entry.name] = {"symlink": os.readlink(entry)}
        else:
            state[entry.name] = {"text": entry.read_text(encoding="utf-8"), "executable": os.access(entry, os.X_OK)}
    return state


def _record_cli() -> list[dict[str, object]]:
    vectors = []
    for case in CLI_CASES:
        with tempfile.TemporaryDirectory(prefix="guard-secrets-vec-") as raw:
            root = Path(raw).resolve()
            for step in case["setup"]:
                _apply(step, root)
            response = _run_request(case["request"], root)
            vector = {**case, "setup": [_encoded(step) for step in case["setup"]]}
            vector["expected"] = _normalize(response, str(root))
            if case.get("hooks"):
                vector["hooks_after"] = _hooks_state(root)
            vectors.append(vector)
    return vectors


def _record_text(repo: Path) -> list[dict[str, object]]:
    import importlib.util
    import inspect

    from codex_plugin_scanner.guard.secrets import secret_detection

    calls: list[dict[str, object]] = []
    original = secret_detection.scan_secret_text

    def recording(text: str, **kwargs: object) -> object:
        summary = original(text, **kwargs)
        calls.append({"text_b64": _b64(text), "kwargs": kwargs, "expected": summary.to_public_dict()})
        return summary

    # Run the text-only tests directly (no pytest session): each module's
    # `scan_secret_text` binding is swapped for the recording wrapper, and
    # parametrized tests are expanded from their marks.
    for relative in TEXT_TEST_MODULES:
        spec = importlib.util.spec_from_file_location(Path(relative).stem, repo / relative)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if getattr(module, "scan_secret_text", None) is not original:
            continue
        module.scan_secret_text = recording
        for name, function in sorted(vars(module).items()):
            if not name.startswith("test_") or not callable(function):
                continue
            parameters = inspect.signature(function).parameters
            marks = [mark for mark in getattr(function, "pytestmark", []) if mark.name == "parametrize"]
            if marks:
                names = (
                    [part.strip() for part in marks[0].args[0].split(",")]
                    if isinstance(marks[0].args[0], str)
                    else list(marks[0].args[0])
                )
                for values in marks[0].args[1]:
                    values = getattr(values, "values", values)
                    values = values if len(names) > 1 else (values,)
                    function(**dict(zip(names, values, strict=True)))
            elif not parameters:
                function()
    for text, kwargs in EXTRA_TEXT_CASES:
        recording(text, **kwargs)
    unique: dict[str, dict[str, object]] = {}
    for call in calls:
        unique.setdefault(json.dumps([call["text_b64"], call["kwargs"]], sort_keys=True), call)
    return list(unique.values())


def main() -> int:
    repo = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2])
    for name in GIT_LOCATION_ENV:
        os.environ.pop(name, None)
    os.environ.update(GIT_ENV)
    from codex_plugin_scanner.guard.secrets.secret_detection import detector_version

    from codex_plugin_scanner.guard.secrets.public_rule_catalog import PUBLIC_RULES_JSON

    payload = {
        "schema": "guard-secrets-cli-vectors.v1",
        "detector_version": detector_version(),
        "rules": json.loads(PUBLIC_RULES_JSON),
        "text": _record_text(repo),
        "cli": _record_cli(),
    }
    output.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"text={len(payload['text'])} cli={len(payload['cli'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
