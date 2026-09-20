"""Runtime regression tests: guard hook codex prompt dotfile scan prefers."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardConfig,
    GuardStore,
    PolicyDecision,
    StdioGuardProxy,
    guard_commands_module,
    io,
    json,
    main,
    pytest,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _FlushTrackingOutput,
    _LineOnlyInput,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_hook_codex_prompt_dotfile_scan_prefers_exact_punctuation_filename(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(workspace_dir / ".authrc", "notes = benign\n")
    _write_text(workspace_dir / ".authrc,", "token = exact-match-secret\n")
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "print ./.authrc,",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["decision"] == "block"
    assert "credential-looking local file" in payload["reason"]


@pytest.mark.parametrize("scope", ["workspace", "global"])
def test_guard_hook_codex_runtime_risk_ignores_broad_allow_policy(
    scope,
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    store = GuardStore(home_dir)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope=scope,
            action="allow",
            workspace=str(workspace_dir) if scope == "workspace" else None,
            reason="broad local allow must not bypass runtime risk",
        ),
        "2026-04-30T00:00:00+00:00",
    )
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "sed -n '1,20p' .authrc"},
        "tool_response": "fake_credential\n",
        "source_scope": "project",
    }
    monkeypatch.setenv("CODEX_HOME", str(home_dir / ".codex"))
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--harness",
            "codex",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["continue"] is True
    assert "HOL Guard" in payload["stopReason"]
    assert "credential-looking output" in payload["stopReason"]


def test_guard_hook_allows_codex_safe_user_prompt_submit_without_output(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    event = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Summarize the README.",
        "source_scope": "project",
    }

    rc, output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
    )
    payload = json.loads(output)

    assert rc == 0
    assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"


def test_stdio_proxy_blocks_disallowed_tools_and_redacts_headers():
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    result = {'echo': message.get('method')}",
                    "    if message.get('method') == 'tools/call':",
                    "        result['tool'] = message.get('params', {}).get('name')",
                    "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}))",
                    "    sys.stdout.flush()",
                ]
            ),
        ],
        blocked_tools={"dangerous"},
    )

    allowed = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "safe-tool",
                    "arguments": {
                        "headers": {
                            "Authorization": "Bearer secret-token",
                            "x-api-key": "hidden",
                        }
                    },
                },
            },
        ]
    )
    blocked = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "dangerous"},
            }
        ]
    )

    assert allowed["responses"][1]["result"]["tool"] == "safe-tool"
    assert allowed["events"][1]["redacted_params"]["arguments"]["headers"]["Authorization"] == "*****"
    assert blocked["responses"][0]["error"]["code"] == -32001
    assert blocked["events"][0]["decision"] == "block"


def test_stdio_proxy_returns_timeout_error_when_child_server_hangs(monkeypatch):
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys, time",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    if message.get('id') is None:",
                    "        continue",
                    "    time.sleep(60)",
                ]
            ),
        ],
    )
    monkeypatch.setattr(proxy, "_response_timeout_seconds", lambda: 0.05)

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ]
    )

    assert result["responses"][0]["error"]["code"] == -32800
    assert result["responses"][0]["error"]["data"]["guard_timeout"] is True
    assert result["responses"][0]["error"]["data"]["source"] == "child_response"
    assert result["events"][0]["decision"] == "timeout"
    assert isinstance(result["return_code"], int)
    assert result["return_code"] != 0


def test_stdio_proxy_waits_for_matching_response_id():
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    print(json.dumps({'jsonrpc': '2.0', 'method': 'tools/progress', 'params': {'step': 1}}))",
                    "    result = {'echo': message.get('method')}",
                    "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}))",
                    "    sys.stdout.flush()",
                ]
            ),
        ],
    )

    result = proxy.run_session(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        ]
    )

    assert result["responses"][0]["id"] == 1
    assert result["responses"][0]["result"]["echo"] == "initialize"


def test_stdio_proxy_stream_does_not_wait_for_notification_replies():
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    if message.get('id') is None:",
                    "        continue",
                    "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'ok': True}}))",
                    "    sys.stdout.flush()",
                ]
            ),
        ],
    )
    output_stream = _FlushTrackingOutput()
    input_stream = _LineOnlyInput(
        [
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n',
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
        ]
    )
    exit_code = proxy.run_stream(
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=io.StringIO(),
    )

    assert exit_code == 0
    assert [json.loads(line) for line in output_stream.getvalue().splitlines()] == [
        {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    ]
    assert input_stream.read_limits


def test_stdio_proxy_stream_forwards_interleaved_notifications():
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    print(json.dumps({'jsonrpc': '2.0', 'method': 'tools/progress', 'params': {'step': 1}}))",
                    "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'ok': True}}))",
                    "    sys.stdout.flush()",
                ]
            ),
        ],
    )
    output_stream = _FlushTrackingOutput()
    input_stream = _LineOnlyInput(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'])

    exit_code = proxy.run_stream(
        input_stream=input_stream,
        output_stream=output_stream,
        error_stream=io.StringIO(),
    )
    output_lines = [json.loads(line) for line in output_stream.getvalue().splitlines()]

    assert exit_code == 0
    assert output_lines == [
        {"jsonrpc": "2.0", "method": "tools/progress", "params": {"step": 1}},
        {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
    ]
    assert input_stream.read_limits


def test_stdio_proxy_blocks_sensitive_file_reads_without_forwarding(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")
    proxy = StdioGuardProxy(
        command=[
            sys.executable,
            "-u",
            "-c",
            "\n".join(
                [
                    "import json, sys",
                    "for line in sys.stdin:",
                    "    message = json.loads(line)",
                    "    result = {'tool': message.get('params', {}).get('name')}",
                    "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}))",
                    "    sys.stdout.flush()",
                ]
            ),
        ],
        cwd=tmp_path / "workspace",
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    allowed = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {
                        "path": "README.md",
                        "headers": {"Authorization": "Bearer secret-token"},
                    },
                },
            }
        ]
    )
    blocked = proxy.run_session(
        [
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {
                        "path": ".env",
                        "headers": {"Authorization": "Bearer secret-token"},
                    },
                },
            }
        ]
    )

    assert allowed["responses"][0]["result"]["tool"] == "read_file"
    assert allowed["events"][0]["decision"] == "forward"
    assert blocked["responses"][0]["error"]["code"] == -32001
    assert "sensitive local file" in blocked["responses"][0]["error"]["message"].lower()
    assert "http://127.0.0.1:4455" in blocked["responses"][0]["error"]["message"]
    assert blocked["responses"][0]["error"]["data"]["approvalCenterUrl"] == "http://127.0.0.1:4455"
    assert blocked["responses"][0]["error"]["data"]["reviewHint"]
    assert blocked["events"][0]["decision"] == "require-reapproval"
    assert blocked["events"][0]["policy_action"] == "require-reapproval"
    assert blocked["events"][0]["transport_outcome"] == "not-forwarded"
    assert blocked["responses"][0]["error"]["data"]["guardPolicyAction"] == "require-reapproval"
    assert blocked["events"][0]["approval_delivery"]["destination"] == "harness"
    assert blocked["events"][0]["redacted_params"]["arguments"]["headers"]["Authorization"] == "*****"
    assert blocked["events"][0]["path_summary"].endswith("/.env")
    pending = store.list_approval_requests(limit=10)
    assert len(pending) == 1
    assert pending[0]["artifact_type"] == "file_read_request"
