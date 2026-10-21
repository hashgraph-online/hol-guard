"""Alternate cleanup captures exact rollback material without publication."""

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.codex_hook_sources import parse_toml_object
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_publication_preparation import _context, _tree
from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture


def _source(tmp_path, monkeypatch, payload):
    context = _context(tmp_path, monkeypatch)
    path = context.home_dir / "workspace/.codex/config.toml"
    path.parent.mkdir(parents=True)
    path.write_text(dump_toml(payload))
    path.chmod(0o644)
    return context, path


def test_hook_cleanup_is_exact_and_preserves_user_hooks(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    managed = adapter._managed_hook_groups(context)["PreToolUse"]
    user = {"matcher": "Bash", "hooks": [{"type": "command", "command": "python user_hook.py"}]}
    lookalike = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo codex_daemon_hook_bridge.py"}]}
    payload = {
        "hooks": {"PreToolUse": [managed, user, lookalike]},
        "features": {"hooks": True, "codex_hooks": True, "other": True},
    }
    context, path = _source(tmp_path, monkeypatch, payload)
    before = _tree(tmp_path)
    change = adapter.prepare_codex_alternate_cleanup(context, config_path=path)
    assert _tree(tmp_path) == before
    rendered = parse_toml_object(change.after, path=path, label="fixture")
    assert rendered["hooks"] == {"PreToolUse": [user, lookalike]}
    assert rendered["features"] == payload["features"]
    assert change.before_mode == 0o644 and change.after_mode == 0o600


def test_combined_cleanup_preserves_proxy_and_unselected_mcp(tmp_path, monkeypatch):
    payload = {
        "model": "fixture",
        "features": {"hooks": True, "other": True},
        "mcp_servers": {
            "original": {"command": "node", "args": ["server.js"]},
            "proxy": {"command": "hol-guard", "args": ["mcp-proxy"]},
            "user": {"command": "node", "args": ["user.js"]},
        },
    }
    context, path = _source(tmp_path, monkeypatch, payload)
    before = _tree(tmp_path)
    change = adapter.prepare_codex_alternate_cleanup(
        context, config_path=path, managed_server_names=("original", "proxy")
    )
    assert _tree(tmp_path) == before
    rendered = parse_toml_object(change.after, path=path, label="fixture")
    assert rendered["features"] == {"other": True}
    assert rendered["model"] == "fixture"
    assert rendered["mcp_servers"] == {key: payload["mcp_servers"][key] for key in ("proxy", "user")}


def test_mcp_only_publication_preserves_mode_and_repeated_cleanup_inode(tmp_path, monkeypatch):
    context, path = _source(tmp_path, monkeypatch, {"mcp_servers": {"original": {"command": "node"}}})
    change = adapter.prepare_codex_alternate_cleanup(
        context, config_path=path, remove_hooks=False, managed_server_names=("original",)
    )
    assert change.after_mode == 0o644
    adapter._publish_codex_alternate_cleanup(change)
    assert path.read_bytes() == b"" and path.stat().st_mode & 0o777 == 0o644
    before = _tree(tmp_path)
    adapter._publish_codex_alternate_cleanup(
        adapter.prepare_codex_alternate_cleanup(
            context, config_path=path, remove_hooks=False, managed_server_names=("original",)
        )
    )
    assert _tree(tmp_path) == before


@pytest.mark.parametrize("payload", [{"mcp_servers": {}}, {"mcp_servers": {"original": {"args": None}}}])
def test_empty_or_malformed_mcp_entries_are_preserved(tmp_path, monkeypatch, payload):
    # TOML has no null: use a malformed scalar for the on-disk args entry.
    if payload.get("mcp_servers", {}).get("original"):
        payload["mcp_servers"]["original"]["args"] = "malformed"
    context, path = _source(tmp_path, monkeypatch, payload)
    change = adapter.prepare_codex_alternate_cleanup(
        context, config_path=path, remove_hooks=False, managed_server_names=("original",)
    )
    assert change.before == change.after


def test_foreign_generation_during_render_is_preserved(tmp_path, monkeypatch):
    context, path = _source(tmp_path, monkeypatch, {"features": {"hooks": True}})
    render = adapter.render_codex_alternate_cleanup

    def foreign_write(*args, **kwargs):
        result = render(*args, **kwargs)
        path.write_text('model = "foreign"\n')
        return result

    monkeypatch.setattr(adapter, "render_codex_alternate_cleanup", foreign_write)
    with pytest.raises(TransitionError, match="generation_changed"):
        adapter.prepare_codex_alternate_cleanup(context, config_path=path)
    assert path.read_text() == 'model = "foreign"\n'
    assert not context.guard_home.exists()


@pytest.mark.parametrize("invalid", [b"\xff", b"model=1\nmodel=2\n"])
def test_invalid_config_is_not_replaced(tmp_path, monkeypatch, invalid):
    context, path = _source(tmp_path, monkeypatch, {})
    path.write_bytes(invalid)
    before = _tree(tmp_path)
    with pytest.raises(RuntimeError):
        adapter.prepare_codex_alternate_cleanup(context, config_path=path)
    assert _tree(tmp_path) == before


def test_signed_cleanup_inverse_restores_bytes_and_mode(
    transition,
    tmp_path,
    monkeypatch,
):
    runtime, plan, _bindings, _pointer = transition
    context, path = _source(tmp_path, monkeypatch, {"features": {"hooks": True, "other": True}})
    change = adapter.prepare_codex_alternate_cleanup(context, config_path=path)
    plan = replace(plan, files=(*plan.files, change))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    assert path.read_bytes() == change.after
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate failed")
    assert path.read_bytes() == change.before
    assert path.stat().st_mode & 0o777 == change.before_mode
