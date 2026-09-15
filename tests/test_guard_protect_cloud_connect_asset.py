from codex_plugin_scanner.guard.daemon import server as daemon_server_module


def test_protect_workspace_starts_local_oauth_connect_flow() -> None:
    fleet_workspace_chunk = (
        daemon_server_module._STATIC_DIR / "assets" / "chunks" / "fleet-workspace.js"
    ).read_text(encoding="utf-8")

    assert "Starting secure Guard Cloud sign-in" in fleet_workspace_chunk
    assert "Open secure sign-in" in fleet_workspace_chunk
    assert "Guard could not generate a secure sign-in link" in fleet_workspace_chunk
