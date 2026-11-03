"""`cloud-actions ai-tools configure --dry-run`: preview one AI tool settings entry.

The preview must never write, must leave every other entry (other MCP servers,
their secrets, Guard Local's own entries, unrelated settings) reading back
exactly as before, and must never show a value Guard did not write.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tomllib

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import cloud_actions_host_config
from codex_plugin_scanner.guard.cli.cloud_actions_host_config import (
    CLOUD_ACTIONS_SERVER_NAME,
    AiToolNotSupportedError,
    plan_host_config,
    settings_path,
)

WS = "11111111-1111-4111-8111-111111111111"
URL = "https://hol.org/api/guard/gateway/mcp"
SECRET = "sk-test-CANARY-7f3a9c"
HEADER_SECRET = "Bearer hdr-CANARY-41be"
QUERY_SECRET = "qs-CANARY-90d2"

# Guard Local's own proxy entry, as `hol-guard install codex` writes it.
CODEX_SETTINGS = f"""# Hand-written; keep this comment.
model = "gpt-5"
approval_policy = "on-request"  # trailing comment

[features]
codex_hooks = true

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = {{ GITHUB_TOKEN = "{SECRET}" }}

[mcp_servers."hol-guard::filesystem"]
command = "/opt/hol-guard/bin/hol-guard"
args = ["codex-mcp-proxy", "--server", "filesystem", "--transport", "stdio"]

[profiles.fast]
model = "gpt-5-mini"
"""

CLAUDE_SETTINGS: dict[str, Any] = {
    "numStartups": 42,
    "oauthAccount": {"emailAddress": "someone@example.test"},
    "projects": {"/work/app": {"mcpServers": {"local": {"command": "node", "args": ["srv.js"]}}}},
    "mcpServers": {
        "linear": {
            "type": "http",
            "url": "https://mcp.linear.example/mcp",
            "headers": {"Authorization": HEADER_SECRET},
        },
        "db": {"command": "pg-mcp", "env": {"PGPASSWORD": SECRET}},
    },
}

CURSOR_SETTINGS: dict[str, Any] = {
    "mcpServers": {
        "hol-guard::filesystem": {"command": "/opt/hol-guard/bin/hol-guard", "args": ["cursor-mcp-proxy"]},
        "notion": {"url": "https://mcp.notion.example/mcp", "headers": {"Authorization": HEADER_SECRET}},
        "db": {"command": "pg-mcp", "env": {"PGPASSWORD": SECRET}},
    }
}

PATHS = {"claude-code": ".claude.json", "codex": ".codex/config.toml", "cursor": ".cursor/mcp.json"}


def _write(home: Path, tool: str, text: str) -> Path:
    path = home / PATHS[tool]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _seed(home: Path, tool: str) -> Path:
    if tool == "codex":
        return _write(home, tool, CODEX_SETTINGS)
    payload = CLAUDE_SETTINGS if tool == "claude-code" else CURSOR_SETTINGS
    return _write(home, tool, json.dumps(payload, indent=2) + "\n")


def _parse(tool: str, raw: bytes) -> dict[str, Any]:
    return tomllib.loads(raw.decode()) if tool == "codex" else json.loads(raw)


def _table(tool: str) -> str:
    return "mcp_servers" if tool == "codex" else "mcpServers"


def _without_guard_entry(tool: str, document: dict[str, Any]) -> dict[str, Any]:
    rest = dict(document)
    servers = {k: v for k, v in rest.get(_table(tool), {}).items() if k != CLOUD_ACTIONS_SERVER_NAME}
    if servers:
        rest[_table(tool)] = servers
    else:
        rest.pop(_table(tool), None)
    return rest


def _configure(home: Path, tool: str, *extra: str) -> int:
    try:
        return cli.main(
            ["cloud-actions", "ai-tools", "configure", tool, "--cloud-workspace", WS, "--home", str(home), *extra]
        )
    except SystemExit as exit_:
        return int(exit_.code or 0)


def _snapshot(home: Path) -> dict[str, bytes]:
    return {str(path.relative_to(home)): path.read_bytes() for path in home.rglob("*") if path.is_file()}


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_preview_adds_only_the_guard_entry_and_writes_nothing(
    tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _seed(tmp_path, tool)
    before_files = _snapshot(tmp_path)

    plan = plan_host_config(tool, path=path, url=URL)
    assert plan.action == "add"
    assert plan.after is not None
    assert plan.before is not None
    assert plan.before == path.read_bytes()
    before, after = _parse(tool, plan.before), _parse(tool, plan.after)
    assert _without_guard_entry(tool, after) == _without_guard_entry(tool, before)
    expected = {"type": "http", "url": URL} if tool == "claude-code" else {"url": URL}
    assert after[_table(tool)][CLOUD_ACTIONS_SERVER_NAME] == expected

    assert _configure(tmp_path, tool, "--dry-run") == 0
    text_out = capsys.readouterr().out
    assert _configure(tmp_path, tool, "--dry-run", "--json") == 0
    json_out = capsys.readouterr().out
    payload = json.loads(json_out)
    assert payload["action"] == "add"
    assert payload["written"] is False
    assert payload["other_entries"] == len(_parse(tool, plan.before)[_table(tool)])
    assert payload["url"] == URL
    assert URL in text_out and "Nothing was written." in text_out
    for leaked in (SECRET, HEADER_SECRET, "someone@example.test", "server-github", "/opt/hol-guard"):
        assert leaked not in text_out + json_out
    assert _snapshot(tmp_path) == before_files


def test_codex_preview_keeps_every_line_and_comment(tmp_path: Path) -> None:
    path = _seed(tmp_path, "codex")

    plan = plan_host_config("codex", path=path, url=URL)

    assert plan.after is not None
    block = f'[mcp_servers.{CLOUD_ACTIONS_SERVER_NAME}]\nurl = "{URL}"\n\n'
    assert plan.after.decode() == CODEX_SETTINGS.replace("[profiles.fast]", block + "[profiles.fast]")


def test_codex_preview_appends_after_the_last_line(tmp_path: Path) -> None:
    path = _write(tmp_path, "codex", 'model = "gpt-5"\n')

    plan = plan_host_config("codex", path=path, url=URL)

    assert plan.after is not None
    assert plan.after.decode() == f'model = "gpt-5"\n\n[mcp_servers.{CLOUD_ACTIONS_SERVER_NAME}]\nurl = "{URL}"\n'


def test_json_preview_keeps_indentation_and_line_endings(tmp_path: Path) -> None:
    original = json.dumps(CURSOR_SETTINGS, indent=4).replace("\n", "\r\n") + "\r\n"
    path = _write(tmp_path, "cursor", original)

    plan = plan_host_config("cursor", path=path, url=URL)

    assert plan.after is not None
    after_text = plan.after.decode()
    assert after_text.endswith("}\r\n")
    assert "\n" not in after_text.replace("\r\n", "")
    assert '\r\n    "mcpServers": {' in after_text


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_preview_of_the_previewed_file_changes_nothing(tool: str, tmp_path: Path) -> None:
    path = _seed(tmp_path, tool)
    first = plan_host_config(tool, path=path, url=URL)
    assert first.after is not None
    path.write_bytes(first.after)

    second = plan_host_config(tool, path=path, url=URL)

    assert second.action == "unchanged"
    assert second.after == first.after


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_new_file_holds_only_the_guard_entry(tool: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = settings_path(tool, home=tmp_path, environ=None)

    plan = plan_host_config(tool, path=path, url=URL)

    assert plan.action == "create_file"
    assert plan.after is not None
    assert list(_parse(tool, plan.after)) == [_table(tool)]
    assert _configure(tmp_path, tool, "--dry-run") == 0
    assert "would be created" in capsys.readouterr().out
    assert not path.exists()
    assert not any(tmp_path.iterdir())


def test_update_shows_the_old_address_without_its_query(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old = f"https://registry-staging.hol.org/api/guard/gateway/mcp?k={QUERY_SECRET}"
    servers = {CLOUD_ACTIONS_SERVER_NAME: {"type": "http", "url": old}, "db": {"command": "x", "env": {"K": SECRET}}}
    _write(tmp_path, "claude-code", json.dumps({"mcpServers": servers}))

    assert _configure(tmp_path, "claude-code", "--dry-run", "--json") == 0
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["action"] == "update"
    assert payload["previous_url"] == "https://registry-staging.hol.org/api/guard/gateway/mcp"
    assert QUERY_SECRET not in out and SECRET not in out


@pytest.mark.parametrize(
    ("old", "shown"),
    [
        ("https://user:pw@[::1]:8443/api/guard/gateway/mcp#frag", "https://[::1]:8443/api/guard/gateway/mcp"),
        ("https://hol.org:99999/api/guard/gateway/mcp", None),
    ],
    ids=["ipv6-with-user", "bad-port"],
)
def test_update_display_drops_user_and_survives_bad_ports(old: str, shown: str | None, tmp_path: Path) -> None:
    path = _write(tmp_path, "cursor", json.dumps({"mcpServers": {CLOUD_ACTIONS_SERVER_NAME: {"url": old}}}))

    plan = plan_host_config("cursor", path=path, url=URL)

    assert plan.action == "update"
    assert plan.previous_url == shown


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "http", "url": URL, "headers": {"Authorization": HEADER_SECRET}},
        {"command": "evil", "env": {"K": SECRET}},
        {"type": "sse", "url": URL},
        "not a table",
    ],
    ids=["extra-headers", "stdio", "other-type", "not-a-table"],
)
def test_entry_with_guard_name_but_other_settings_is_never_replaced(
    entry: object, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path, "claude-code", json.dumps({"mcpServers": {CLOUD_ACTIONS_SERVER_NAME: entry}}))

    assert _configure(tmp_path, "claude-code", "--dry-run", "--json") == 1
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["action"] == "conflict"
    assert payload["written"] is False
    assert HEADER_SECRET not in out and SECRET not in out and "evil" not in out


def test_another_entry_for_the_same_server_is_reported_not_duplicated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path, "cursor", json.dumps({"mcpServers": {"guard": {"url": URL + "/"}}}))

    assert _configure(tmp_path, "cursor", "--dry-run", "--json") == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["action"] == "already_configured"
    assert payload["configured_as"] == ["guard"]


@pytest.mark.parametrize(
    ("tool", "content"),
    [
        ("cursor", '{"mcpServers": {'),
        ("cursor", f'{{"mcpServers": {{}}, "mcpServers": {{"db": {{"env": {{"K": "{SECRET}"}}}}}}}}'),
        ("cursor", "[1, 2]"),
        ("cursor", f'{{"mcpServers": ["{SECRET}"]}}'),
        ("claude-code", '﻿{"a": 1}'),
        ("codex", f'mcp_servers = "{SECRET}"\n'),
        ("codex", f'key = "{SECRET}\n'),
    ],
    ids=["truncated", "repeated-key", "array", "servers-not-table", "bom", "toml-servers-string", "toml-broken"],
)
def test_unreadable_settings_are_left_alone_and_not_echoed(
    tool: str, content: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, tool, content)
    before = path.read_bytes()

    assert _configure(tmp_path, tool, "--dry-run", "--json") == 1
    out = capsys.readouterr().out

    assert json.loads(out)["action"] == "unreadable"
    assert SECRET not in out
    assert path.read_bytes() == before


def test_settings_path_that_is_a_folder_is_unreadable(tmp_path: Path) -> None:
    path = tmp_path / ".cursor" / "mcp.json"
    path.mkdir(parents=True)

    assert plan_host_config("cursor", path=path, url=URL).action == "unreadable"


def test_settings_path_follows_the_ai_tool_home_unless_home_is_given(tmp_path: Path) -> None:
    env = {"CODEX_HOME": str(tmp_path / "codex-home"), "CLAUDE_CONFIG_DIR": str(tmp_path / "claude-home")}

    assert settings_path("codex", home=tmp_path, environ=env) == tmp_path / "codex-home" / "config.toml"
    assert settings_path("claude-code", home=tmp_path, environ=env) == tmp_path / "claude-home" / ".claude.json"
    assert settings_path("cursor", home=tmp_path, environ=env) == tmp_path / ".cursor" / "mcp.json"
    assert settings_path("codex", home=tmp_path, environ=None) == tmp_path / ".codex" / "config.toml"
    with pytest.raises(AiToolNotSupportedError):
        _ = settings_path("windsurf", home=tmp_path, environ=env)


def test_unsupported_ai_tool_names_the_supported_ones(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _configure(tmp_path, "windsurf", "--dry-run", "--json") == 3
    payload = json.loads(capsys.readouterr().out)

    assert payload["reason"] == "ai_tool_not_supported"
    assert payload["supported_ai_tools"] == ["claude-code", "codex", "cursor"]


def test_apply_is_not_available_yet_and_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _seed(tmp_path, "cursor")
    before = path.read_bytes()

    assert _configure(tmp_path, "cursor", "--apply", "--json") == 3

    assert json.loads(capsys.readouterr().out)["reason"] == "not_available_yet"
    assert path.read_bytes() == before


def test_cloud_url_off_hol_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _configure(tmp_path, "cursor", "--dry-run", "--json", "--cloud-url", "https://evil.example") == 1

    assert json.loads(capsys.readouterr().out)["reason"] == "cloud_url_not_allowed"
    assert not any(tmp_path.iterdir())


def test_cloud_url_sets_the_address(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _configure(tmp_path, "codex", "--dry-run", "--json", "--cloud-url", "http://127.0.0.1:3061/points") == 0

    assert json.loads(capsys.readouterr().out)["url"] == "http://127.0.0.1:3061/api/guard/gateway/mcp"


def test_home_option_ignores_the_ai_tool_home_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "elsewhere"))

    assert _configure(tmp_path, "codex", "--dry-run", "--json") == 0

    assert json.loads(capsys.readouterr().out)["settings_file"] == str(tmp_path / ".codex" / "config.toml")


@pytest.mark.parametrize("tool", sorted(PATHS))
def test_a_rendering_that_changes_another_entry_is_refused(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed(tmp_path, tool)
    honest = cloud_actions_host_config._render_edit  # pyright: ignore[reportPrivateUsage]

    def lossy(ai_tool: object, before: bytes, url: str) -> bytes:
        return honest(ai_tool, before.replace(SECRET.encode(), b"changed"), url)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(cloud_actions_host_config, "_render_edit", lossy)

    plan = plan_host_config(tool, path=path, url=URL)

    assert plan.action == "unreadable"
    assert plan.after is None
