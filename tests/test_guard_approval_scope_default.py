from codex_plugin_scanner.guard.cli.approval_commands import _requested_approval_scope


def test_cli_approval_uses_request_recommended_scope_when_scope_is_omitted() -> None:
    request = {
        "recommended_scope": "workspace",
        "recommended_scope_by_action": {"allow": "workspace", "block": "artifact"},
    }
    assert _requested_approval_scope(None, request, "allow") == "workspace"
    assert _requested_approval_scope(None, request, "block") == "artifact"
    assert _requested_approval_scope("publisher", request, "allow") == "publisher"
    assert _requested_approval_scope(None, {"recommended_scope": "unsupported"}, "allow") == "artifact"
