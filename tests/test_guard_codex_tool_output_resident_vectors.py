"""Parity vectors recorded from the retired Python Codex tool-output review.

The vectors were recorded from the Python implementation that preceded the
``codex_tool_output`` resident op. This suite replays a deterministic slice of
the shared corpus through the thin Python wrappers and the real resident; the
Rust suite replays the full corpus against the same fixture.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support as support
from codex_plugin_scanner.guard.cli import commands_support_codex_commands as codex_commands
from codex_plugin_scanner.guard.cli import commands_support_codex_tool_output as codex_tool_output
from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as runtime_artifacts
from codex_plugin_scanner.guard.native_codex_tool_output import codex_tool_output_native

pytestmark = [
    pytest.mark.skipif(
        not (os.environ.get("HOL_GUARD_NATIVE_REGRESSION") == "1" and os.environ.get("HOL_GUARD_NATIVE_BINARY")),
        reason="native runtime binary is not provisioned for this run",
    ),
    pytest.mark.skipif(sys.platform == "win32", reason="the Codex tool-output review models POSIX paths"),
]

_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "tests"
    / "fixtures"
    / "codex_tool_output_vectors.json"
)
_SLICE_STRIDE = 11
_GIT_ENVIRONMENT_PREFIXES = ("GIT_", "LD_", "DYLD_")


def _git(root: Path, repository: str, *args: str) -> None:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(root / "proc"),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(
        ["git", *args],
        cwd=root / repository,
        env=environment,
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="module")
def corpus() -> dict[str, object]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def tree(
    corpus: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is unavailable")
    root = tmp_path.resolve() / "vectors"
    for directory in corpus["dirs"]:  # type: ignore[attr-defined]
        (root / str(directory)).mkdir(parents=True, exist_ok=True)
    for name, text in corpus["files"].items():  # type: ignore[attr-defined]
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for link, target in corpus["symlinks"].items():  # type: ignore[attr-defined]
        (root / link).symlink_to(target)
    for repository in corpus["git_repos"]:  # type: ignore[attr-defined]
        _git(root, repository["path"], "init", "-q")
        for key, value in repository["config"]:
            _git(root, repository["path"], "config", key, value)
        _git(root, repository["path"], "add", "-A")
    for name in tuple(os.environ):
        if name.upper().startswith(_GIT_ENVIRONMENT_PREFIXES):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.chdir(root / "proc")
    return root


def _slice(corpus: dict[str, object]) -> list[dict[str, object]]:
    return list(corpus["cases"][::_SLICE_STRIDE])  # type: ignore[index]


def _paths(case: dict[str, object], root: Path) -> tuple[str, Path | None, Path | None]:
    command = str(case["command"]).replace("${ROOT}", str(root))
    cwd = None if case["cwd"] is None else root / str(case["cwd"])
    home = None if case["home_dir"] is None else root / str(case["home_dir"])
    return command, cwd, home


def _mismatches(corpus: dict[str, object], root: Path, key: str, probe) -> list[str]:
    failures: list[str] = []
    checked = 0
    for case in _slice(corpus):
        expected = case["expected"].get(key)  # type: ignore[attr-defined]
        if expected is None:
            continue
        command, cwd, home = _paths(case, root)
        checked += 1
        actual = probe(command, cwd, home)
        if actual is not expected:
            failures.append(f"{key} {command!r} cwd={case['cwd']} expected={expected} actual={actual}")
    assert checked > 100
    return failures


def test_read_only_inspection_matches_the_retired_python_vectors(corpus: dict[str, object], tree: Path) -> None:
    failures = _mismatches(
        corpus,
        tree,
        "ro",
        lambda command, cwd, home: support._codex_command_is_read_only_source_inspection(
            command, cwd=cwd, home_dir=home
        ),
    )
    assert not failures, failures[:10]


def test_secret_like_source_names_match_the_retired_python_vectors(corpus: dict[str, object], tree: Path) -> None:
    plain = _mismatches(
        corpus,
        tree,
        "sn",
        lambda command, cwd, home: (
            codex_tool_output_native(
                "secret_like_source_name", command=command, cwd=cwd, home_dir=home, exec_context=False
            ).allowed
        ),
    )
    contextual = _mismatches(
        corpus,
        tree,
        "sx",
        lambda command, cwd, home: codex_tool_output._codex_command_targets_secret_like_source_name(
            command, cwd=cwd, home_dir=home
        ),
    )
    assert not plain, plain[:10]
    assert not contextual, contextual[:10]


def test_local_content_reads_match_the_retired_python_vectors(corpus: dict[str, object], tree: Path) -> None:
    failures = _mismatches(
        corpus,
        tree,
        "full",
        lambda command, cwd, _home: support._codex_command_may_read_local_content(command, cwd=cwd),
    )
    assert not failures, failures[:10]


def test_environment_pipelines_and_focused_pytest_match_the_retired_python_vectors(
    corpus: dict[str, object], tree: Path
) -> None:
    environment = _mismatches(
        corpus,
        tree,
        "envp",
        lambda command, _cwd, _home: codex_commands._codex_command_reads_environment_pipeline(command),
    )
    pytest_cases = _mismatches(
        corpus,
        tree,
        "pytest",
        lambda command, _cwd, _home: codex_tool_output._codex_command_is_focused_pytest_verification(command),
    )
    assert not environment, environment[:10]
    assert not pytest_cases, pytest_cases[:10]


def test_git_pathspec_identity_presence_matches_the_retired_python_vectors(
    corpus: dict[str, object], tree: Path
) -> None:
    failures = _mismatches(
        corpus,
        tree,
        "id",
        lambda command, cwd, _home: (
            runtime_artifacts._codex_git_pathspec_identity_for_command(command, cwd=cwd) is not None
        ),
    )
    assert not failures, failures[:10]


def test_unencodable_observed_values_are_denied_with_a_typed_code(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANG", "en_US\udcff")
    answer = codex_tool_output_native("read_only_inspection", command="cat src/a.py", cwd=tree / "home" / "proj")
    assert answer.allowed is False
    assert answer.error_code == "native_codex_tool_output_invalid"
