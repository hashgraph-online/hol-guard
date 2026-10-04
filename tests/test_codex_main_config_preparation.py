"""Global Codex render and backup contracts used by transition composition."""

from copy import deepcopy
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.adapters import codex as adapter
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer
from codex_plugin_scanner.guard.codex_config import dump_toml
from codex_plugin_scanner.guard.runtime_transition import TransitionError

from .test_codex_publication_preparation import _context, _tree
from .test_runtime_transition import begin, transition  # noqa: F401 -- shared pytest fixture


@pytest.mark.parametrize(
    "original,migrated",
    [(None, None), (b'# comment\nmodel="fixture"\n', None), (b'model="fixture"\n', {"model": "fixture", "hooks": {}})],
)
def test_backup_preparation_preserves_content_rule_without_writes(tmp_path, monkeypatch, original, migrated):
    context = _context(tmp_path, monkeypatch)
    before = _tree(tmp_path)
    change = adapter.prepare_codex_main_backup(context, original=original, migrated_payload=migrated)
    assert _tree(tmp_path) == before
    assert change.before is None
    assert change.after == (dump_toml(migrated).encode() if migrated is not None else original or b"")
    assert change.after_mode == 0o600
    assert not context.guard_home.exists()


def test_existing_backup_retains_bytes_mode_and_inode(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    path = adapter.CodexHarnessAdapter._backup_path(context)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"prior backup generation")
    path.chmod(0o640)
    before = _tree(tmp_path)
    change = adapter.prepare_codex_main_backup(context, original=b"new config")
    adapter._publish_codex_alternate_cleanup(change)
    assert _tree(tmp_path) == before
    assert change.before == change.after == b"prior backup generation"
    assert change.before_mode == change.after_mode == 0o640


def test_backup_foreign_generation_before_publication_is_preserved(tmp_path, monkeypatch):
    context = _context(tmp_path, monkeypatch)
    change = adapter.prepare_codex_main_backup(context, original=b"original config")
    change.path.parent.mkdir(parents=True)
    change.path.write_bytes(b"foreign backup")
    with pytest.raises(TransitionError, match="generation_changed"):
        adapter._publish_codex_alternate_cleanup(change)
    assert change.path.read_bytes() == b"foreign backup"


def _server(context, name, scope="global"):
    root = context.home_dir if scope == "global" else context.workspace_dir
    path = root / ".codex/config.toml"
    return ManagedMcpServer("codex", name, scope, str(path), "node", ("server.js",), "stdio", {}, True)


def test_mcp_renderer_refreshes_proxy_preserves_input_and_workspace_precedence(tmp_path, monkeypatch):
    context = replace(_context(tmp_path, monkeypatch), workspace_dir=tmp_path / "workspace")
    monkeypatch.setattr(adapter, "_guard_python_executable", lambda: "/fixture/current-python")
    payload = {
        "model": "fixture",
        "mcp_servers": {
            "prior": {
                "command": "/old/python",
                "args": ["-m", "codex_plugin_scanner.cli", "guard", "codex-mcp-proxy"],
                "env": {"FIXTURE": "retained"},
            },
            "shadow": {"command": "node"},
            "user": {"command": "unselected"},
        },
    }
    workspace = {"mcp_servers": {"shadow": {"command": "workspace"}, "project": {"command": "node"}}}
    originals = deepcopy((payload, workspace))
    before = _tree(tmp_path)
    rendered, migrated = adapter.render_codex_managed_mcp(
        context,
        payload,
        workspace_payload=workspace,
        managed_servers=(_server(context, "shadow"), _server(context, "project", "project")),
    )
    assert (payload, workspace) == originals
    assert _tree(tmp_path) == before
    assert migrated == ("prior",)
    servers = rendered["mcp_servers"]
    assert servers["prior"] == {**payload["mcp_servers"]["prior"], "command": "/fixture/current-python"}
    assert "shadow" not in servers
    assert servers["user"] == payload["mcp_servers"]["user"]
    assert "codex-mcp-proxy" in servers["project"]["args"]
    assert rendered["model"] == "fixture"


@pytest.mark.parametrize("existing", [False, True])
def test_signed_backup_inverse_preserves_prior_generation(
    transition,
    tmp_path,
    monkeypatch,
    existing,
):
    runtime, plan, _bindings, _pointer = transition
    context = _context(tmp_path, monkeypatch)
    path = adapter.CodexHarnessAdapter._backup_path(context)
    if existing:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"prior backup")
        path.chmod(0o640)
    change = adapter.prepare_codex_main_backup(context, original=b"original config")
    plan = replace(plan, files=(*plan.files, change))
    begin(runtime, plan)
    runtime.publish(plan.operation_id, "AuthorizedForExactTransition")
    runtime.publish(plan.operation_id, "HooksPrepared")
    runtime.restore_files(plan.operation_id, first_cause="fixture candidate failed")
    if existing:
        assert path.read_bytes() == change.before
        assert path.stat().st_mode & 0o777 == change.before_mode
    else:
        assert not path.exists()
