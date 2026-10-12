"""Synthetic inputs for SFRS entry points the existing suites exercise too thinly.

Run under the recorder (``-p scripts.ci.sfrs_vector_recorder``) so each call is
captured from the Python implementation with its directory snapshot.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

SERVICES = "codex_plugin_scanner.guard.runtime.secret_file_request_services"
READ_TOOLS = ("Read", "read_file", "view", "cat_file", "open_file", "Grep", "")
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "write_file", "StrReplace", "Delete", "Read")
SENSITIVE = (
    ".env",
    ".env.local",
    "config/.env.production",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.npmrc",
    "~/.netrc",
    "~/.config/gh/hosts.yml",
    "~/.docker/config.json",
    "~/.kube/config",
    "secrets/server.pem",
    "id_rsa",
    "notes.txt",
    "README.md",
    "src/app.py",
    "~/.cursor/mcp.json",
    "~/.claude/settings.json",
    ".git/config",
)


def _fn(module: str, name: str):
    return getattr(importlib.import_module(f"{SERVICES}.{module}"), name)


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    work = tmp_path / "work"
    for target in (home / ".ssh", home / ".aws", home / ".cursor", home / ".claude", work / "src", work / "config"):
        target.mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text("key", encoding="utf-8")
    (home / ".aws" / "credentials").write_text("[default]", encoding="utf-8")
    (work / ".env").write_text("A=1", encoding="utf-8")
    (work / "README.md").write_text("hello", encoding="utf-8")
    (work / "src" / "app.py").write_text("print(1)", encoding="utf-8")
    (work / "notes.txt").write_text("n", encoding="utf-8")
    return home, work


@pytest.mark.parametrize("path", SENSITIVE)
def test_classify_sensitive_path_supplement(tmp_path: Path, path: str) -> None:
    home, work = _layout(tmp_path)
    classify = _fn("request_models", "classify_sensitive_path")
    classify(path, cwd=work, home_dir=home)
    classify(f"'{path}'", cwd=work, home_dir=home)
    classify(str(work / path), cwd=work, home_dir=home)
    classify(path, cwd=None, home_dir=home)
    classify(path, cwd=work, home_dir=None)


def test_classify_sensitive_path_degenerate_inputs(tmp_path: Path) -> None:
    home, work = _layout(tmp_path)
    classify = _fn("request_models", "classify_sensitive_path")
    for value in (None, "", "   ", "''", "~", ".", "..", "../outside/.env", "a/../.env"):
        classify(value, cwd=work, home_dir=home)


@pytest.mark.parametrize("tool", WRITE_TOOLS)
@pytest.mark.parametrize("path", SENSITIVE)
def test_file_write_supplement(tmp_path: Path, tool: str, path: str) -> None:
    home, work = _layout(tmp_path)
    extract = _fn("request_artifacts", "extract_sensitive_file_write_request")
    build = _fn("request_artifacts", "build_file_write_request_artifact")
    protected = {str(home / ".cursor" / "mcp.json"): "Cursor MCP configuration"}
    for arguments in (
        {"file_path": path},
        {"path": path, "content": "x"},
        {"paths": [path]},
    ):
        for use_protected in (None, protected):
            match = extract(tool, arguments, cwd=work, home_dir=home, protected_paths=use_protected)
            if match is not None:
                for scope in ("project", "global"):
                    build("codex", match, config_path=str(work / "hooks.json"), source_scope=scope)


@pytest.mark.parametrize("tool", READ_TOOLS)
@pytest.mark.parametrize("path", SENSITIVE)
def test_file_read_supplement(tmp_path: Path, tool: str, path: str) -> None:
    home, work = _layout(tmp_path)
    extract = _fn("request_models", "extract_sensitive_file_read_request")
    build = _fn("request_artifacts", "build_file_read_request_artifact")
    benign = _fn("benign_requests", "is_explicitly_benign_native_file_read_request")
    for arguments in (
        {"file_path": path},
        {"path": path},
        {"path": path, "file_path": path},
        {"path": path, "file_path": "src/app.py"},
        {"paths": [path]},
        {"path": " " + path + " "},
        {"path": path + "$X"},
        {"path": path + ";x"},
    ):
        match = extract(tool, arguments, cwd=work, home_dir=home)
        if match is not None:
            for scope in ("project", "global"):
                build("claude-code", match, config_path=str(work / "settings.json"), source_scope=scope)
        benign(tool, arguments, cwd=work, home_dir=home)
    benign(tool, "not-a-dict", cwd=work, home_dir=home)
    benign(tool, {"path": str(work / "README.md")}, cwd=work, home_dir=home)
    benign(tool, {"path": str(work / "src")}, cwd=work, home_dir=home)
    benign(tool, {"path": "missing.txt"}, cwd=work, home_dir=home)


def test_command_list_candidate_texts_supplement() -> None:
    candidates = _fn("request_artifacts", "command_list_candidate_texts")
    samples: list[list[str]] = [
        [],
        [""],
        ["  "],
        ["ls"],
        ["  ls  "],
        ["ls", "-la"],
        ["echo", "a b", "c"],
        ["echo", "it's", '"q"'],
        ["cat", ".env", ""],
        ["git", "status", "&&", "ls"],
        ["a", "", "b"],
        ["bash", "-lc", "echo $HOME"],
        ["rm", "-rf", "build dir"],
        ["printf", "%s\n", "x"],
    ]
    for sample in samples:
        for preserve in (False, True):
            candidates(sample, preserve_items=preserve)
    candidates(["ls", 3, None, "-l"], preserve_items=False)  # type: ignore[list-item]
    candidates(["ls", 3, None, "-l"], preserve_items=True)  # type: ignore[list-item]
