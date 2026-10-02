"""Extra metadata reads stay indexed; listing never becomes blanket file access."""

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import restricted_linux_namespace as namespace
from codex_plugin_scanner.guard.runtime import restricted_pytest_model as model
from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox


@pytest.mark.parametrize("with_system_library", [False, True])
def test_linked_metadata_has_listing_without_parent_checkout_or_secret_read_grants(
    monkeypatch, tmp_path, with_system_library
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "ordinary.txt").write_text("ordinary")
    parent = tmp_path / "other-checkout"
    metadata = parent / ".git"
    metadata.mkdir(parents=True)
    (metadata / "HEAD").write_text("ref: refs/heads/main\n")
    (metadata / ".env").write_text("synthetic fixture")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    executable = tmp_path / "bin" / "git"
    executable.parent.mkdir()
    executable.write_bytes(b"\x7fELF")
    monkeypatch.setattr(sys, "platform", "linux")
    library = tmp_path / "library"
    library.mkdir()
    (library / "ordinary.dat").write_text("ordinary runtime data")
    (library / ".env").write_text("synthetic fixture")
    monkeypatch.setattr(model, "_LINUX_READ_ROOTS", (library,) if with_system_library else ())
    monkeypatch.setattr(model, "_LINUX_READ_FILES", ())
    monkeypatch.setattr(sandbox, "_runtime_read_roots", lambda plan: ())
    monkeypatch.setattr(namespace, "resolve_linux_elf_loader", lambda path: None)
    monkeypatch.setattr(namespace, "collect_mapping_evidence", lambda **kwargs: [])
    plan = model.RestrictedPytestPlan(
        profile_version=model.GIT_READ_ONLY_PROFILE_VERSION,
        backend="linux-bubblewrap",
        backend_executable=Path("/usr/bin/bwrap"),
        workspace=workspace,
        cwd=workspace,
        command=(str(executable), "diff", "--stat"),
        executable=executable,
        allowed_executables=(executable,),
        read_only_roots=(metadata,),
        denied_capabilities=("workspace-write", "workspace-credential-read", "network"),
    )
    argv = namespace.linux_readonly_argv(plan, private_root=private)
    snapshot = json.loads((private / "linux-plan.json").read_text())
    assert snapshot["schema"] == "guard-linux-readonly-plan.v2"
    assert "mapping_records" in snapshot
    assert snapshot["list_roots"] == [str(workspace), *([str(library)] if with_system_library else []), str(metadata)]
    assert snapshot["read_roots"] == []
    assert str(metadata / "HEAD") in snapshot["read_files"]
    assert str(metadata / ".env") not in snapshot["read_files"]
    assert str(library / ".env") not in snapshot["read_files"]
    assert (str(library / "ordinary.dat") in snapshot["read_files"]) is with_system_library
    assert str(parent) not in argv
    assert snapshot["write_roots"] == [str(private)]
    assert "--unshare-all" in argv and argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "CAP_SYS_ADMIN" in argv and "CAP_SETPCAP" in argv
    assert "/guard-approved-mappings" in argv
