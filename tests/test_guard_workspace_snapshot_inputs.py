from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs import (
    complete_workspace_snapshot,
    reject_external_node_modules,
)


def _write(path: Path, content: str = "content\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


def test_complete_snapshot_is_deterministic_and_omits_guard_state(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _write(workspace / "src" / "example.ts")
    _write(workspace / "package.json", "{}\n")
    _write(workspace / "node_modules" / "runner" / "index.js")
    _write(workspace / ".git" / "config", "must-not-cross\n")
    _write(workspace / ".guard" / "state.json", "must-not-cross\n")

    first = complete_workspace_snapshot(workspace)
    second = complete_workspace_snapshot(workspace)

    assert first == second
    paths = tuple(item.snapshot_path for item in first[1])
    assert paths == tuple(sorted(paths))
    assert paths == ("node_modules/runner/index.js", "package.json", "src/example.ts")


@pytest.mark.parametrize(
    "protected_path",
    (
        ".env",
        ".env.example",
        ".git-credentials",
        ".npmrc",
        ".vault-token",
        "credentials.json",
        "nested/.ssh/config",
        "nested/.docker/config.json",
        "nested/.kube/config",
        "nested/service-account.json",
        "runtime/APIToken.json",
        "runtime/apiToken.json",
        "runtime/clientSecret.json",
        "runtime/id_dsa",
        "runtime/id_ecdsa",
        "runtime/id_ed25519",
        "runtime/id_rsa",
        "runtime/privateKey.json",
        "runtime/serviceAccount.json",
        "runtime/token.txt",
        "terraform.tfvars",
        "tls/client.key",
        "wallet.key",
    ),
)
def test_protected_presence_requires_review_without_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    protected_path: str,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    protected = workspace / protected_path
    _write(protected, "must-not-read\n")
    original_read = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path == protected:
            pytest.fail("protected workspace content was read")
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)

    with pytest.raises(ValueError, match="protected workspace content"):
        _ = complete_workspace_snapshot(workspace)


def test_symlink_requires_review(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _write(workspace / "src" / "example.ts")
    (workspace / "escape").symlink_to("/usr/bin/true")

    with pytest.raises(ValueError, match="cannot contain symlinks"):
        _ = complete_workspace_snapshot(workspace)


def test_symlinked_package_bin_directory_requires_review(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _write(workspace / "src" / "example.ts")
    package_bin = workspace / "node_modules" / ".bin"
    package_bin.parent.mkdir(parents=True)
    package_bin.symlink_to(workspace / "src", target_is_directory=True)

    with pytest.raises(ValueError, match="cannot contain symlinks"):
        _ = complete_workspace_snapshot(workspace)


def test_excluded_state_presence_changes_snapshot_identity(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _write(workspace / "src" / "example.ts")
    without_state = complete_workspace_snapshot(workspace)[0]
    _write(workspace / ".git" / "HEAD", "ref: refs/heads/release\n")

    with_state = complete_workspace_snapshot(workspace)[0]

    assert with_state != without_state


def test_hard_link_requires_review(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    source = workspace / "source.txt"
    _write(source)
    (workspace / "alias.txt").hardlink_to(source)

    with pytest.raises(ValueError, match="hard-linked"):
        _ = complete_workspace_snapshot(workspace)


@pytest.mark.skipif(os.name == "nt", reason="descriptor traversal is Unix-specific")
def test_directory_replacement_during_traversal_requires_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    directory = workspace / "src"
    _write(directory / "example.ts")
    original_open = os.open
    replaced = False

    def replacing_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777) -> int:
        nonlocal replaced
        if Path(os.fsdecode(path)) == directory and not replaced:
            replaced = True
            _ = directory.rename(workspace / "src-original")
            directory.mkdir()
        return original_open(path, flags, mode)

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs.os.open", replacing_open)

    with pytest.raises(ValueError, match="directory identity changed"):
        _ = complete_workspace_snapshot(workspace)


@pytest.mark.parametrize("budget", ("files", "bytes", "entries", "time"))
def test_snapshot_enforces_hard_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget: str,
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    _write(workspace / "one.txt", "one\n")
    _write(workspace / "two.txt", "two\n")
    module = "codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs"
    if budget == "files":
        monkeypatch.setattr(f"{module}._MAX_FILES", 1)
    elif budget == "bytes":
        monkeypatch.setattr(f"{module}._MAX_BYTES", 1)
    elif budget == "entries":
        monkeypatch.setattr(f"{module}._MAX_ENTRIES", 1)
    else:
        observed = iter((0.0, 10.0))
        monkeypatch.setattr(f"{module}.time.monotonic", lambda: next(observed))

    with pytest.raises(ValueError, match="budget"):
        _ = complete_workspace_snapshot(workspace)


def test_external_node_modules_requires_review(tmp_path: Path) -> None:
    project = (tmp_path / "project").resolve()
    workspace = project / "packages" / "app"
    workspace.mkdir(parents=True)
    _write(project / "node_modules" / "ambient" / "index.js")

    with pytest.raises(ValueError, match="external Node dependencies"):
        reject_external_node_modules(workspace)
