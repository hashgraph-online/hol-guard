from __future__ import annotations

from codex_plugin_scanner.guard.runtime.secret_file_request_services.benign_requests import (
    is_explicitly_benign_tool_action_request,
)


def test_release_allowlist_is_used_by_production_benign_request_path(tmp_path) -> None:
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": "gh pr view 42 --json title"},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
