"""Record `server_id_vectors.json` from the Python `stable_mcp_server_identifier`.

The reference below is the pure-Python implementation `guard/adapters/mcp_servers.py`
carried before the `server_id` op moved it into the native runtime.

    python rust/crates/guard-runtime/testdata/harness_mcp_discovery/record_server_id_vectors.py
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path, PurePosixPath

SCHEMA = "guard-mcp-server-id-vectors.v1"
OUTPUT = Path(__file__).with_name("server_id_vectors.json")
_STABLE_SLASH_FLAG_TOKENS = frozenset(
    {
        "/?",
        "/debug",
        "/dry-run",
        "/h",
        "/help",
        "/quiet",
        "/read-only",
        "/readonly",
        "/ro",
        "/safe",
        "/trace",
        "/verbose",
    }
)


def stable_mcp_server_identifier(server: dict[str, object]) -> str:
    harness = str(server["harness"]).strip().lower()
    source_scope = str(server["source_scope"]).strip().lower()
    server_name = str(server["name"]).strip().lower() or "unnamed"
    payload = {
        "harness": harness,
        "source_scope": source_scope,
        "name": server_name,
        "command": PurePosixPath(str(server["command"]).replace("\\", "/")).name.lower(),
        "args": [_stable_arg_token(str(value)) for value in server["args"]],  # type: ignore[union-attr]
        "transport": server["transport"],
    }
    digest = sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:20]
    return f"mcp_server:{harness}:{source_scope}:{server_name}:{digest}"


def _stable_arg_token(value: str) -> str:
    key, separator, item = value.partition("=")
    if separator and (_looks_like_path_assignment(key, item) or _looks_like_path_token(item)):
        return f"{key}=<path>"
    if _looks_like_path_token(value):
        return "<path>"
    return value


def _looks_like_path_assignment(key: str, value: str) -> bool:
    normalized_key = key.strip().lstrip("-/").lower().replace("_", "-")
    path_keys = {
        "cache",
        "config",
        "cwd",
        "dir",
        "directory",
        "file",
        "folder",
        "path",
        "root",
        "workspace",
        "workdir",
    }
    return normalized_key in path_keys and value.strip().replace("\\", "/").startswith("/")


def _looks_like_path_token(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if normalized.startswith(("~/", "./", "../")):
        return True
    if normalized.startswith("/"):
        return "/" in normalized[1:] or normalized.lower() not in _STABLE_SLASH_FLAG_TOKENS
    return len(normalized) >= 3 and normalized[0].isalpha() and normalized[1:3] == ":/"


def _server(harness: str, name: str, scope: str, command: str, args: list[str], transport: str) -> dict[str, object]:
    return {
        "harness": harness,
        "name": name,
        "source_scope": scope,
        "command": command,
        "args": args,
        "transport": transport,
    }


SERVERS = [
    _server("codex", "github", "global", "npx", ["-y", "@modelcontextprotocol/server-github"], "stdio"),
    _server(" Codex ", " GitHub ", " Project ", "/usr/local/bin/NPX", [], "stdio"),
    _server("cursor", "", "workspace", "node", ["./server.js"], "stdio"),
    _server("claude-code", "   ", "global", "uvx", ["mcp-server-fetch"], "local"),
    _server("copilot", "files", "global", "node", ["/srv/app/index.js", "--root=/srv/data"], "stdio"),
    _server("cline", "files", "global", "C:\\Tools\\Node.EXE", ["C:\\srv\\index.js", "--dir=C:/x"], "stdio"),
    _server("hermes", "flags", "global", "tool", ["/help", "/HELP", "/verbose", "/verbose/x", "/x"], "stdio"),
    _server("hermes", "assign", "global", "tool", ["--Work_Dir= /q", "cwd=/a", "name=value", "path=rel"], "stdio"),
    _server("opencode", "home", "global", "tool", ["~/x", "../y", "~", "a=./b"], "stdio"),
    _server("codex", "drives", "global", "tool", ["1:/x", "é:/x", "c:/", "c:"], "stdio"),
    _server("codex", "Ünïcödé Ñame", "glöbal", "tööl", ["ärg", "😀", "\u00a0spaced\u00a0"], "stdio"),
    _server("codex", "quotes", "global", "tool", ['say "hi"', "back\\slash", "tab\there", "nl\nx", "\u0001"], ""),
    _server("CODEX", "ẞig", "GLOBAL", "/usr/bin/", ["İ"], "STDIO"),
    _server("codex", "dots", "global", "a/.", [], "stdio"),
    _server("codex", "empty-command", "global", "", [], "stdio"),
    _server("codex", "colon:name", "scope:x", "python3", ["-m", "pkg.server", "--config=/etc/x.json"], "stdio"),
]


def main() -> None:
    cases = [{"server": server, "expected": stable_mcp_server_identifier(server)} for server in SERVERS]
    document = {"schema": SCHEMA, "cases": cases}
    OUTPUT.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
