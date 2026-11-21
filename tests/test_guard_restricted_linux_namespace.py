"""The Linux namespace plan is prepared natively from the plan's profile fields.

The native resident owns discovery, the snapshot and argv; its grant and
listing contracts are covered by the Rust plan tests.
"""

import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import restricted_linux_namespace as namespace
from codex_plugin_scanner.guard.runtime import restricted_pytest_model as model


def test_readonly_argv_sends_only_profile_fields_to_native_preparation(monkeypatch, tmp_path):
    """Verify readonly argv sends only profile fields to native preparation."""
    workspace = tmp_path / "workspace"
    executable = Path("/usr/bin/git")
    private = tmp_path / "private"
    metadata = tmp_path / "other-checkout" / ".git"
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
    calls = []

    def native(operation, fields, expected):
        calls.append((operation, fields, expected))
        return ["/usr/bin/bwrap", "--", "helper", "restricted-linux-launch", "f" * 64]

    monkeypatch.setattr(namespace, "linux_native", native)
    argv = namespace.linux_readonly_argv(plan, private_root=private)
    assert argv[-2:] == ["restricted-linux-launch", "f" * 64]
    [(operation, fields, expected)] = calls
    assert (operation, expected) == ("linux_readonly_argv", list)
    assert fields == {
        "profile_version": model.GIT_READ_ONLY_PROFILE_VERSION,
        "workspace": workspace,
        "cwd": workspace,
        "allowed_executables": (executable,),
        "read_only_roots": (metadata,),
        "output_roots": (),
        "command": (str(executable), "diff", "--stat"),
        "backend_executable": Path("/usr/bin/bwrap"),
        "private_root": private,
        "backend": "linux-bubblewrap",
        "platform": sys.platform,
    }
