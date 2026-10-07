"""The execution CLI preserves authority checks and validated snapshot cleanup."""

from argparse import Namespace
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as cli
from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError


@pytest.mark.parametrize("failed", [False, True])
def test_zcode_dispatch_cleans_validated_requests_even_when_execution_fails(tmp_path, monkeypatch, failed):
    from codex_plugin_scanner.guard.cli import commands_hook_native_authority as authority

    directory = tmp_path / "hol-guard-contained-test-dispatch"
    directory.mkdir()
    request = directory / "request.json"
    request.write_text("synthetic")
    original = {"tool_input": {"command": "bunx vitest run"}}
    monkeypatch.setattr(sink, "read_contained_test_request", lambda *args, **kwargs: original)
    receipt = {"decision": "deny", "required_execution_profile": "vitest-readonly-v1"}

    def authorize(**kwargs):
        assert kwargs["harness"] == "zcode"
        assert kwargs["payload"] == {**original, "guard_containment_receipt_only": True}
        return receipt

    monkeypatch.setattr(authority, "try_native_hook_authority", authorize)

    def execute(payload, **kwargs):
        assert payload is original
        assert kwargs["authorize"](payload) is receipt
        if failed:
            raise RestrictedPytestError("synthetic_denial", "denied")
        return 0

    monkeypatch.setattr(sink, "run_authorized_contained_test", execute)
    args = Namespace(request_file=str(request), request_sha256="a" * 64, harness="zcode", timeout_seconds=30)
    result = cli._run_guard_execute_contained_test_command(
        args,
        guard_home=tmp_path,
        workspace=tmp_path,
        context=SimpleNamespace(home_dir=tmp_path),
        store=object(),
    )
    assert result == (126 if failed else 0)
    assert not request.exists()
    assert not directory.exists()
