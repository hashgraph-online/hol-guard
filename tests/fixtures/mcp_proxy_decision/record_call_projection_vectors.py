"""Record `call_projection` vectors from the pre-change MCP proxy helpers.

Run once, at commit bf8e617b24, against the Python proxy that still owned the
separate projections
(`_safe_mcp_arguments`, `_safe_mcp_params`, `_launch_target`,
`_browser_intent_payload`, `tool_call_risk_categories` and
`tool_call_risk_summary`), with a native runtime and a throwaway HOME:

    HOME=$(mktemp -d) HOL_GUARD_NATIVE=force HOL_GUARD_NATIVE_BINARY=<runtime> \
        python record_call_projection_vectors.py call_projection_vectors.json
"""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.mcp_tool_calls import (
    build_tool_call_artifact,
    tool_call_risk_categories,
    tool_call_risk_summary,
)
from codex_plugin_scanner.guard.native_mcp_tool_evidence import risk_input
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity

_SERVERS = {
    "chrome": ("chrome-devtools", ("-y", "@modelcontextprotocol/server-chrome-devtools")),
    "chrome_debug": (
        "chrome-devtools",
        ("-y", "@modelcontextprotocol/server-chrome-devtools", "--remote-debugging-port=9222"),
    ),
    "playwright": ("playwright", ("-y", "@playwright/mcp")),
    "filesystem": ("filesystem", ("-y", "@modelcontextprotocol/server-filesystem", "/srv")),
    "github": ("github", ("-y", "@modelcontextprotocol/server-github")),
}


def _artifact(server: str, tool_name: str, *, server_args: list[str] | None = None):
    server_name, args = _SERVERS[server]
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name=server_name,
        tool_name=tool_name,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=build_mcp_server_identity(config_path=".mcp.json", command="npx", args=args, transport="stdio"),
    )
    if server_args is not None:
        artifact.metadata["server_args"] = server_args
    return artifact


_SECRET = "sk-live-0123456789abcdef0123456789abcdef"
_ABSENT = object()

# (label, tool name, server or None, arguments or _ABSENT, extra params, server_args)
_CASES: list[tuple[str, str, str | None, object, dict[str, object], list[str] | None]] = [
    ("plain_mapping", "read_file", None, {"path": "README.md"}, {}, None),
    ("absent_arguments", "list_tools", None, _ABSENT, {}, None),
    ("null_arguments", "list_tools", None, None, {}, None),
    ("string_arguments", "run", None, '{"cmd": "ls"}', {}, None),
    ("list_arguments", "run", None, ["a", 1, None, True], {}, None),
    ("number_arguments", "run", None, 7.5, {}, None),
    ("empty_mapping", "run", None, {}, {}, None),
    ("secret_keys", "call_api", None, {"api_key": _SECRET, "token": "t0k", "query": "x"}, {}, None),
    ("url_query_secret", "fetch", None, {"url": f"https://api.example.com/v1?access_token={_SECRET}&q=1"}, {}, None),
    (
        "nested_secrets",
        "call",
        None,
        {"auth": {"password": "hunter2", "user": "a"}, "list": [{"secret": "s"}]},
        {},
        None,
    ),
    ("unicode", "write", None, {"text": "héllo ✓ 😀", "path": "/tmp/ü"}, {"_meta": {"progressToken": 3}}, None),
    ("big_numbers", "calc", None, {"n": 12345678901234567890, "f": 1e300, "neg": -0.0}, {}, None),
    ("fs_read", "read_file", "filesystem", {"path": "/srv/.env"}, {}, None),
    ("fs_write", "write_file", "filesystem", {"path": "/srv/a.txt", "content": "hi"}, {}, None),
    ("fs_absent", "list_allowed_directories", "filesystem", _ABSENT, {}, None),
    ("github_secret", "create_issue", "github", {"repo": "o/r", "body": f"token {_SECRET}"}, {}, None),
    ("chrome_navigate_https", "navigate_page", "chrome", {"url": "https://hol.org/guard?x=1#y"}, {}, None),
    (
        "chrome_navigate_local",
        "navigate_page",
        "chrome",
        {"type": "url", "url": "http://127.0.0.1:3000/guard"},
        {},
        None,
    ),
    (
        "chrome_debug_profile",
        "navigate_page",
        "chrome_debug",
        {"type": "url", "url": "http://127.0.0.1:3000/guard"},
        {},
        ["--remote-debugging-port=9222"],
    ),
    ("chrome_file_url", "navigate_page", "chrome", {"url": "file:///etc/passwd"}, {}, None),
    ("chrome_js_url", "navigate_page", "chrome", {"url": "javascript:alert(1)"}, {}, None),
    ("chrome_empty_url", "navigate_page", "chrome", {"url": ""}, {}, None),
    ("chrome_query_secret", "navigate_page", "chrome", {"url": f"https://a.example/cb?code={_SECRET}"}, {}, None),
    ("chrome_volatile", "navigate_page", "chrome", {"url": "https://hol.org", "timeout": 5, "pageId": 2}, {}, None),
    ("chrome_screenshot", "take_screenshot", "chrome", {}, {}, None),
    ("chrome_screenshot_absent", "take_screenshot", "chrome", _ABSENT, {}, None),
    ("chrome_evaluate", "evaluate_script", "chrome", {"function": "() => document.cookie"}, {}, None),
    ("chrome_fill_password", "fill", "chrome", {"uid": "1_2", "value": "hunter2"}, {}, None),
    ("chrome_string_args", "navigate_page", "chrome", '{"url": "https://hol.org/a"}', {}, None),
    ("chrome_bad_json_args", "navigate_page", "chrome", "{not json", {}, None),
    ("playwright_navigate", "browser_navigate", "playwright", {"url": "https://github.com/login"}, {}, None),
    ("playwright_cookies", "browser_evaluate", "playwright", {"function": "() => localStorage"}, {}, None),
    ("playwright_type", "browser_type", "playwright", {"element": "pw", "text": "secret!", "ref": "e1"}, {}, None),
    ("playwright_close", "browser_close", "playwright", _ABSENT, {"_meta": None}, None),
    ("playwright_list_args", "browser_navigate", "playwright", ["https://hol.org"], {}, None),
]


def _params(tool_name, arguments, extra) -> dict[str, object]:
    params: dict[str, object] = {"name": tool_name, **extra}
    if arguments is not _ABSENT:
        params["arguments"] = arguments
    return params


def _query(tool_name, server, params, server_args) -> dict[str, object]:
    risk = None
    if server is not None:
        risk = risk_input(_artifact(server, tool_name, server_args=server_args), params.get("arguments"))
    return {"check": "call_projection", "tool_name": tool_name, "params": params, "risk": risk}


def _record(label, tool_name, server, arguments, extra, server_args) -> dict[str, object]:
    params = _params(tool_name, arguments, extra)
    args = params.get("arguments")
    launch_target = runtime_mcp.RuntimeMcpGuardProxy._launch_target(tool_name, args)
    expected: dict[str, object] = {
        "safe_arguments": runtime_mcp._safe_mcp_arguments(args),
        "safe_params": runtime_mcp._safe_mcp_params(params),
        "launch_target": launch_target,
        "browser": None,
        "risk": None,
    }
    if server is not None:
        artifact = _artifact(server, tool_name, server_args=server_args)
        browser_target, browser_intent = runtime_mcp._browser_intent_payload(
            artifact, args, default_launch_target=launch_target
        )
        if browser_intent is not None:
            expected["browser"] = {"launch_target": browser_target, "intent": browser_intent}
        expected["risk"] = {
            "risk_categories": list(tool_call_risk_categories(artifact, args)),
            "summary": tool_call_risk_summary(artifact, args),
        }
    return {"label": label, "query": _query(tool_name, server, params, server_args), "expected": expected}


def main(out_path: str) -> None:
    vectors = []
    for case in _CASES:
        try:
            vectors.append(_record(*case))
        except ValueError as error:
            label, tool_name, server, arguments, extra, server_args = case
            query = _query(tool_name, server, _params(tool_name, arguments, extra), server_args)
            vectors.append({"label": label, "query": query, "expected": {"error": str(error).split(":")[0]}})
    document = {
        "description": "call_projection parity vectors recorded from the pre-change Python MCP proxy helpers",
        "vectors": vectors,
    }
    Path(out_path).write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"recorded {len(vectors)} vectors, browser={sum(1 for v in vectors if (v['expected'].get('browser')))}")


if __name__ == "__main__":
    main(sys.argv[1])
