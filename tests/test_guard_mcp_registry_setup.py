from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime import mcp_registry_setup
from codex_plugin_scanner.guard.store import GuardStore

_SELECTION = {"registry_name": "io.github.ComposioHQ/composio", "version": "1.0.5",
              "endpoint": "https://connect.composio.dev/mcp", "setup_name": "composio"}


def _listing(_query: str) -> dict[str, object]:
    assert _query == _SELECTION["registry_name"]
    return {"results": [{"name": _SELECTION["registry_name"], "version": _SELECTION["version"],
                         "status": "active", "remote_endpoints": [{"url": _SELECTION["endpoint"],
                                                                     "transport": "streamable-http"}]}]}


def test_setup_preview_binds_exact_listing_and_requires_local_proof(tmp_path: Path, monkeypatch):
    store = GuardStore(tmp_path / "home")
    service = LocalCliApiService(store=store)
    monkeypatch.setattr(mcp_registry_setup, "search_mcp_registry", _listing)
    launched = []
    monkeypatch.setattr(mcp_registry_setup, "install_codex_remote_mcp", lambda candidate: launched.append(candidate))
    preview = service.registry_setup({"operation": "preview", **_SELECTION})
    assert preview["kind"] == "remote"
    assert preview["permissions_granted"] is False and preview["host_change_applied"] is False
    assert len(preview["selection_digest"]) == 64 and launched == []
    for endpoint in ("http://connect.composio.dev/mcp", "https://user@connect.composio.dev/mcp",
                     "https://connect.composio.dev/mcp?token=secret"):
        with pytest.raises(LocalCliApiError):
            service.registry_setup({"operation": "preview", **_SELECTION, "endpoint": endpoint})
    with pytest.raises(LocalCliApiError) as mismatch:
        service.registry_setup({"operation": "apply", **_SELECTION, "selection_digest": "f" * 64,
                                "confirm_host_change": True, "session_nonce": "n" * 32})
    assert mismatch.value.status == 409 and launched == []
    with pytest.raises(LocalCliApiError) as proof:
        service.registry_setup({"operation": "apply", **_SELECTION, "selection_digest": preview["selection_digest"],
                                "confirm_host_change": True, "session_nonce": "n" * 32})
    assert proof.value.status == 423 and launched == []
    update_settings(store.guard_home, {"enabled": True, "new_password": "synthetic-test-password",
                                       "confirm_password": "synthetic-test-password", "cooldown_seconds": 0})
    with pytest.raises(LocalCliApiError):
        service.registry_setup({"operation": "apply", **_SELECTION, "selection_digest": preview["selection_digest"],
                                "confirm_host_change": True, "session_nonce": "x" * 32,
                                "approval_password": "wrong-password"})
    assert launched == []
    result = service.registry_setup({"operation": "apply", **_SELECTION,
                                     "selection_digest": preview["selection_digest"],
                                     "confirm_host_change": True, "session_nonce": "y" * 32,
                                     "approval_password": "synthetic-test-password"})
    assert result["host_change_applied"] is True and result["permissions_granted"] is False
    assert len(launched) == 1


def test_codex_cli_setup_checks_existing_and_verifies_exact_endpoint(monkeypatch):
    candidate = {**_SELECTION, "selection_digest": "b" * 64}
    monkeypatch.setattr(mcp_registry_setup.shutil, "which", lambda name: "/synthetic/codex")
    calls = []

    def execute(args, **kwargs):
        calls.append(args)
        assert kwargs["capture_output"] is True and kwargs["timeout"] <= 10
        if args[2] == "get" or (len(args) > 2 and args[1:3] == ["mcp", "get"]):
            if len(calls) == 1:
                return subprocess.CompletedProcess(args, 1, b"", b"Error: No MCP server named 'composio' found.")
            return subprocess.CompletedProcess(args, 0, json.dumps({"url": candidate["endpoint"]}).encode(), b"")
        return subprocess.CompletedProcess(args, 0, b"Added", b"")

    monkeypatch.setattr(mcp_registry_setup.subprocess, "run", execute)
    assert mcp_registry_setup.install_codex_remote_mcp(candidate) == "composio"
    assert calls == [["/synthetic/codex", "mcp", "get", "--json", "composio"],
                     ["/synthetic/codex", "mcp", "add", "composio", "--url", candidate["endpoint"]],
                     ["/synthetic/codex", "mcp", "get", "--json", "composio"]]

    def existing(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, b"{}", b"")

    calls.clear()
    monkeypatch.setattr(mcp_registry_setup.subprocess, "run", existing)
    with pytest.raises(ValueError, match="codex_connection_already_exists"):
        mcp_registry_setup.install_codex_remote_mcp(candidate)


def test_package_setup_revalidates_pinned_recipe_and_requires_local_proof(tmp_path: Path, monkeypatch):
    selection = {"kind": "package", "registry_name": "io.github.example/server", "version": "1.0.0",
                 "package_identifier": "@example/server", "package_version": "2.3.4", "setup_name": "example"}
    option = {"registry_type": "npm", "identifier": "@example/server", "version": "2.3.4",
              "command": "npx", "arguments": ["-y", "@example/server@2.3.4"], "transport": "stdio",
              "verified_package": False}
    listing = {"results": [{"name": selection["registry_name"], "version": "1.0.0",
                            "status": "active", "package_options": [option]}]}
    def search(query: str):
        assert query == selection["registry_name"]
        return listing

    monkeypatch.setattr(mcp_registry_setup, "search_mcp_registry", search)
    monkeypatch.setattr(mcp_registry_setup.shutil, "which", lambda _name: "/synthetic/npx")
    installed = []
    monkeypatch.setattr(
        mcp_registry_setup, "install_codex_package_mcp", lambda candidate: installed.append(candidate) or "example"
    )
    store = GuardStore(tmp_path / "home")
    service = LocalCliApiService(store=store)
    preview = service.registry_setup({"operation": "preview", **selection})
    with pytest.raises(LocalCliApiError) as invalid_kind:
        service.registry_setup({"operation": "preview", **selection, "kind": "unknown"})
    assert invalid_kind.value.status == 400
    assert preview["command"] == "/synthetic/npx" and preview["arguments"] == option["arguments"]
    assert preview["permissions_granted"] is False and installed == []
    apply = {"operation": "apply", **selection, "selection_digest": preview["selection_digest"],
             "confirm_host_change": True, "session_nonce": "n" * 32}
    with pytest.raises(LocalCliApiError) as no_proof:
        service.registry_setup(apply)
    assert no_proof.value.status == 423 and installed == []
    update_settings(store.guard_home, {"enabled": True, "new_password": "synthetic-test-password",
                                       "confirm_password": "synthetic-test-password", "cooldown_seconds": 0})
    listing["results"][0]["package_options"] = []
    with pytest.raises(LocalCliApiError) as changed:
        service.registry_setup({**apply, "approval_password": "synthetic-test-password"})
    assert changed.value.status == 409 and installed == []
    listing["results"][0]["package_options"] = [option]
    result = service.registry_setup({**apply, "approval_password": "synthetic-test-password"})
    assert result["host_change_applied"] is True and result["permissions_granted"] is False
    assert len(installed) == 1


def test_codex_package_setup_uses_argv_and_checks_result(monkeypatch):
    monkeypatch.setattr(mcp_registry_setup.shutil, "which", lambda name: f"/synthetic/{name}")
    candidate = {"setup_name": "example", "command": "/synthetic/npx", "arguments": ["-y", "@example/server@2.3.4"]}
    calls = []

    def execute(args, **kwargs):
        calls.append(args)
        assert kwargs["capture_output"] is True and kwargs["timeout"] <= 10
        if len(calls) == 1:
            return subprocess.CompletedProcess(args, 1, b"", b"Error: No MCP server named 'example' found.")
        if len(calls) == 2:
            return subprocess.CompletedProcess(args, 0, b"Added", b"")
        return subprocess.CompletedProcess(args, 0, json.dumps({"transport": {
            "type": "stdio", "command": candidate["command"], "args": candidate["arguments"]}}).encode(), b"")

    monkeypatch.setattr(mcp_registry_setup.subprocess, "run", execute)
    assert mcp_registry_setup.install_codex_package_mcp(candidate) == "example"
    assert calls[1] == [
        "/synthetic/codex", "mcp", "add", "example", "--", "/synthetic/npx", "-y", "@example/server@2.3.4"
    ]
    calls.clear()

    def changed(args, **kwargs):
        response = execute(args, **kwargs)
        if len(calls) == 3:
            return subprocess.CompletedProcess(args, 0, b'{"transport":{"command":"other","args":[]}}', b"")
        return response

    monkeypatch.setattr(mcp_registry_setup.subprocess, "run", changed)
    with pytest.raises(ValueError, match="codex_setup_outcome_uncertain"):
        mcp_registry_setup.install_codex_package_mcp(candidate)


@pytest.mark.parametrize("kind", ["remote", "package"])
def test_long_single_component_registry_name_uses_bounded_substring_and_exact_match(kind, monkeypatch):
    name = "a" * 100
    queries = []
    entry = {"name": name, "version": "1.0.0", "status": "active",
             "remote_endpoints": [{"url": "https://example.com/mcp", "transport": "streamable-http"}],
             "package_options": [{"registry_type": "pypi", "identifier": "example-server", "version": "2.0.0",
                                  "command": "uvx", "arguments": ["example-server@2.0.0"], "verified_package": False}]}

    def search(query):
        queries.append(query)
        return {"results": [entry]}

    monkeypatch.setattr(mcp_registry_setup, "search_mcp_registry", search)
    payload = {"registry_name": name, "version": "1.0.0", "setup_name": "example"}
    if kind == "package":
        monkeypatch.setattr(mcp_registry_setup.shutil, "which", lambda _name: "/synthetic/uvx")
        candidate = mcp_registry_setup.reviewed_codex_package_candidate(
            {**payload, "package_identifier": "example-server", "package_version": "2.0.0"}
        )
    else:
        candidate = mcp_registry_setup.reviewed_codex_setup_candidate(
            {**payload, "endpoint": "https://example.com/mcp"}
        )
    assert candidate["kind"] == kind and len(candidate["selection_digest"]) == 64
    assert queries == [name[-80:]]
