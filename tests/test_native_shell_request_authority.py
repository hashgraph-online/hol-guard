"""The public adapters preserve native ownership and command-level batching."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_shell_request_authority as native
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


@pytest.fixture
def bridge(monkeypatch):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="a" * 64, path=Path("/runtime")),
        capabilities=SimpleNamespace(features=["runner-authority-v1", "resident-protocol-v2"]),
    )
    calls = []
    flags = {
        "_gh_pr_create_body_has_shell_command_substitution": False,
        "_gh_pr_create_has_active_shell_expansion": False,
        "_gh_pr_edit_has_shell_command_substitution": True,
    }

    def answer(kind, args, home):
        calls.append((kind, args, home))
        return {"value": None, "flags": dict(flags)}

    native._FLAGS.clear()
    monkeypatch.setattr(native, "_native_runtime_status_memo", lambda: status)
    monkeypatch.setattr(native, "_resolve_digest_home", lambda _: Path("/guard"))
    monkeypatch.setattr(native, "native_resident_client_ready", lambda *_: True)
    monkeypatch.setattr(native, "native_runner_authority", answer)
    monkeypatch.setattr(native, "_environment_snapshot", lambda: {})
    monkeypatch.setattr(native, "_account_home_directory", lambda: None)
    monkeypatch.setattr(native, "_process_groups", lambda: [])
    return status, calls


def test_one_classification_supplies_all_pure_flags(bridge):
    _, calls = bridge
    command = "gh pr edit 1 --body literal"
    assert (
        native.shell_request_authority(
            "classify_github_shell_capabilities", {"command_text": command, "home_dir": Path("/home")}
        )
        is None
    )
    for entry, expected in (
        ("_gh_pr_create_body_has_shell_command_substitution", False),
        ("_gh_pr_create_has_active_shell_expansion", False),
        ("_gh_pr_edit_has_shell_command_substitution", True),
    ):
        assert native.shell_request_authority(entry, {"command_text": command}) is expected
    assert len(calls) == 1
    assert calls[0][1]["arguments"]["home_dir"] == "/home"


def test_runtime_identity_and_resident_loss_invalidate_reuse(bridge, monkeypatch):
    status, calls = bridge
    entry = "_gh_pr_edit_has_shell_command_substitution"
    args = {"command_text": "gh pr edit 1"}
    native.shell_request_authority(entry, args)
    status.identity.sha256 = "b" * 64
    native.shell_request_authority(entry, args)
    monkeypatch.setattr(native, "native_resident_client_ready", lambda *_: False)
    native.shell_request_authority(entry, args)
    assert len(calls) == 3


def test_outage_never_uses_previous_native_flags(bridge):
    status, calls = bridge
    entry = "_gh_pr_edit_has_shell_command_substitution"
    args = {"command_text": "gh pr edit 1"}
    native.shell_request_authority(entry, args)
    status.available = False
    with pytest.raises(NativeRunnerAuthorityError):
        native.shell_request_authority(entry, args)
    assert len(calls) == 1


def test_cache_is_bounded_and_classifications_are_never_cached(bridge):
    _, calls = bridge
    for index in range(140):
        native.shell_request_authority(
            "_gh_pr_edit_has_shell_command_substitution", {"command_text": f"gh pr edit {index}"}
        )
    assert len(native._FLAGS) == 128
    args = {"command_text": "gh pr list", "home_dir": None}
    native.shell_request_authority("classify_github_shell_capabilities", args)
    native.shell_request_authority("classify_github_shell_capabilities", args)
    assert len(calls) == 142


@pytest.mark.parametrize(
    "entry",
    ["_gh_pr_create_uses_safe_static_body_file", "_gh_pr_edit_uses_safe_static_body_file"],
)
def test_static_body_proof_remains_fresh_and_command_level(bridge, entry):
    _, calls = bridge
    args = {"command_text": "gh pr create --body-file body.md", "cwd": Path("/workspace"), "home_dir": None}
    native.shell_request_authority(entry, args)
    native.shell_request_authority(entry, args)
    assert len(calls) == 2
    assert all(call[1]["entry"] == entry and "facts" in call[1] for call in calls)
    assert calls[0][1]["arguments"]["cwd"] == "/workspace"
