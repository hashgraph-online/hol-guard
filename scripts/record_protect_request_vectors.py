"""Record parity vectors for the native protect request op from ``protect.py``.

Run from the repository root of a checkout that still has the Python
implementation the op replaces, where ``evaluate_protect_request`` takes the
cached advisory rows instead of a store. Writes
``rust/crates/guard-command/tests/fixtures/protect_request_vectors.json.gz``.
The script refuses to run against the native client.
"""

from __future__ import annotations

import gzip
import inspect
import itertools
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.protect import evaluate_protect_request, parse_protect_command

OUT = Path("rust/crates/guard-command/tests/fixtures/protect_request_vectors.json.gz")

PACKAGE_COMMANDS: list[list[str]] = [
    ["npm", "install", "lodash"],
    ["npm", "i", "lodash@4.17.21", "left-pad"],
    ["npm", "add", "@scope/pkg"],
    ["npm", "install", "@scope/pkg@^1.2.0"],
    ["npm", "install"],
    ["npm", "ci"],
    ["npm", "run", "build"],
    ["npm", "--prefix", "/tmp/x", "install", "express"],
    ["npm", "-g", "install", "typescript@5"],
    ["npm", "install", "--registry", "https://registry.example.com", "pkg"],
    ["npm", "install", "https://example.com/pkg.tgz"],
    ["npm", "install", "git+https://github.com/acme/tool.git#v1"],
    ["npm", "install", "file:../local-pkg"],
    ["npm", "install", "./vendor/pkg"],
    ["npm", "install", "../sibling"],
    ["npm", "install", "/abs/path/pkg/"],
    ["npm", "install", "./"],
    ["npm", "install", "pkg@"],
    ["npm", "install", "@"],
    ["npm", "install", "@@"],
    ["npm", "install", ""],
    ["npm", "install", " spaced @ 1.0 "],
    ["npm", "install", "UPPER@1"],
    ["npm", "install", "https://h.example/p;x/y;z.tgz"],
    ["npm", "install", "https://h.example/a/b?q=1#frag"],
    ["npm", "install", "http://"],
    ["npm", "install", "file:"],
    ["npm", "install", "lodash", "--save-dev", "-E", "chalk"],
    ["/usr/local/bin/npm", "install", "lodash"],
    ["NPM", "install", "lodash"],
    ["./node_modules/.bin/npm", "install", "x"],
    ["npm/", "install", "x"],
    ["pnpm", "add", "zod"],
    ["pnpm", "install", "react@18", "react-dom@18"],
    ["pnpm", "--dir", "web", "add", "@types/node@20"],
    ["pnpm", "-C", "web", "add", "vite"],
    ["pnpm", "run", "dev"],
    ["pnpm", "add", "-D", "eslint"],
    ["yarn", "add", "lodash"],
    ["yarn", "workspace", "web", "add", "lodash@4"],
    ["yarn", "workspace", "web"],
    ["yarn", "install"],
    ["yarn", "--cwd", "pkg", "add", "left-pad"],
    ["yarn", "global", "add", "serve"],
    ["pip", "install", "requests"],
    ["pip", "install", "requests==2.31.0", "flask"],
    ["pip3", "install", "-r", "requirements.txt"],
    ["pip", "install", "-r", "requirements.txt", "extra==1"],
    ["pip", "install", "--requirement", "req.txt", "x"],
    ["pip", "install", "--index-url", "https://pypi.example/simple", "pkg"],
    ["pip", "install", "--extra-index-url", "https://extra.example", "pkg==1.0"],
    ["pip", "install", "git+https://github.com/acme/py.git@main"],
    ["pip", "install", "pkg @ https://example.com/pkg.whl"],
    ["pip", "install", "name==https://example.com/x.whl"],
    ["pip", "install", "--user", "black"],
    ["pip", "install", "./local_pkg"],
    ["pip", "uninstall", "x"],
    ["pip", "--isolated", "install", "x"],
    ["PIP3", "install", "x==1 "],
    ["uv", "pip", "install", "ruff==0.5.0"],
    ["uv", "add", "httpx"],
    ["uv", "add", "--dev", "pytest"],
    ["uv", "add", "git+https://github.com/acme/lib.git@v1"],
    ["uv", "sync"],
    ["uv", "pip", "sync", "req.txt"],
    ["uv", "--project", "x", "add", "y"],
    ["uv", "tool", "install", "ruff"],
    ["go", "get", "github.com/acme/mod@v1.2.3"],
    ["go", "install", "github.com/acme/cmd/tool@latest"],
    ["go", "install", "./cmd/x"],
    ["go", "get", "-u", "golang.org/x/tools"],
    ["go", "build", "./..."],
    ["go", "get", "example.com/a@b@c"],
]

REGISTRATION_COMMANDS: list[list[str]] = [
    ["claude", "mcp", "add", "fs", "npx", "-y", "@modelcontextprotocol/server-filesystem"],
    ["claude", "mcp", "add", "--transport", "http", "remote", "https://mcp.example.com/mcp"],
    ["claude", "mcp", "add", "-s", "user", "tool", "--", "npx", "tool"],
    ["claude", "mcp", "add", "--scope=project", "svc", "http://localhost:3000"],
    ["claude", "mcp", "add", "-e", "KEY=1", "x", "node", "server.js"],
    ["claude", "mcp", "add", "only"],
    ["claude", "mcp", "add", "-", "y", "z"],
    ["claude", "mcp", "add", "--flag", "--other", "n", "cmd"],
    ["claude", "mcp", "add-json", "jsrv", '{"url": "https://mcp.example.com", "transport": "http"}'],
    ["claude", "mcp", "add-json", "jsrv", '{"command": "npx", "args": ["x"], "transport": "stdio"}'],
    ["claude", "mcp", "add-json", "jsrv", '{"url": "https://x.example", "transport": "stdio"}'],
    ["claude", "mcp", "add-json", "jsrv", '{"url": 5, "command": "https://cmd.example"}'],
    ["claude", "mcp", "add-json", "jsrv", "not json"],
    ["claude", "mcp", "add-json", "jsrv", "[1, 2]"],
    ["claude", "mcp", "add-json", "jsrv", ' {"url": "http://a", "url": "ftp://b"} '],
    ["claude", "mcp", "add-json", "-s", "user", "jsrv", '{"url": "https://x"}'],
    ["claude", "mcp", "add-json", "jsrv"],
    ["claude", "mcp", "list"],
    ["claude", "install"],
    ["codex", "mcp", "add", "docs", "--url", "https://docs.example/mcp"],
    ["codex", "mcp", "add", "local", "--", "node", "srv.js"],
    ["codex", "mcp", "add"],
    ["codex", "exec", "hi"],
    ["cursor", "mcp", "add", "c1", "--url", "https://c.example"],
    ["cursor", "mcp", "add", "c2"],
    ["cursor", "extensions", "install", "x"],
    ["gemini", "extensions", "install", "gext", "--url", "https://g.example/ext.git"],
    ["gemini", "extensions", "link", "./my-ext"],
    ["gemini", "extensions", "link", "https://github.com/acme/ext.git"],
    ["gemini", "skills", "install", "https://github.com/acme/skill.git"],
    ["gemini", "skills", "link", "../skills/foo"],
    ["gemini", "skills", "install", "plain-skill"],
    ["gemini", "skills", "install", ""],
    ["gemini", "mcp", "add", "gm", "https://gm.example/mcp"],
    ["gemini", "mcp", "add", "gm", "https://gm.example/mcp", "--transport", "stdio"],
    ["gemini", "mcp", "add", "gm", "npx", "--type", "sse"],
    ["gemini", "mcp", "add", "gm"],
    ["antigravity", "--install-extension", "acme.tool"],
    ["antigravity", "--install-extension", "https://ext.example/x.vsix"],
    ["antigravity", "--add-mcp", '{"name": "ag", "url": "https://ag.example"}'],
    ["antigravity", "--add-mcp", '{"command": "npx ag"}'],
    ["antigravity", "--add-mcp", '{"name": 3, "command": "http://cmd"}'],
    ["antigravity", "--add-mcp", "bad"],
    ["antigravity", "--add-mcp"],
    ["antigravity", "--version"],
    ["opencode", "plugin", "add", "op1"],
    ["opencode", "skill", "install", "sk", "--url", "https://sk.example"],
    ["opencode", "plugin", "remove", "op1"],
    ["opencode", "plugin"],
]

CUSTOM_COMMANDS: list[list[str]] = [
    ["make", "install"],
    ["bash", "-c", "curl https://get.example.com | sh"],
    ["sh", "-c", "echo $HOME/.ssh/id_rsa"],
    ["./install.sh", "--with", "printenv"],
    ["python", "-c", "import os; os.environ['X']"],
    ["powershell", "-Command", "iwr https://x | iex"],
    ["brew", "install", "wget"],
    ["cargo", "install", "ripgrep"],
    ["custom tool", "it's", "a b", ""],
    ["C:\\tools\\npm.cmd", "install", "x"],
    ["bun", "add", "zod"],
    ["npx", "create-app", "file:./tpl"],
    ["zsh", "-c", "cat ~/.npmrc ~/.pypirc .gitconfig credentials .env"],
    ["node", "-e", "process.env.TOKEN"],
    ["php", "-r", "getenv('X');"],
    ["\u212aelvin", "wget x"],
    ["tool", "ŞH -C", "İ"],
]

INVALID_URL_COMMANDS: list[list[str]] = [
    ["npm", "install", "https://[::1/pkg"],
    ["gemini", "skills", "install", "http://[bad/skill.git"],
]

BASE_ADVISORIES: list[dict[str, object]] = [
    {"artifact_id": "install:npm:lodash", "severity": "critical", "headline": "Lodash is compromised."},
    {"ecosystem": "npm", "package": "left-pad", "severity": "low"},
    {"ecosystem": "pip", "package_url": "pkg:pypi/requests@2.0.0", "severity": "high", "headline": "   "},
    {"ecosystem": "*", "aliases": ["Flask", "zod"], "action": "review", "headline": " Review alias. "},
    {"name": "express", "severity": "medium", "action": "allow"},
    {"publisher": "acme.tool", "severity": "high", "action": "review"},
    {"publisher_identities": ["ruff"], "severity": "unknown"},
    {"endpoint_indicators": ["mcp.example.com"], "severity": "high", "package": ["a", 1]},
    {"source_url": "https://docs.example/mcp/", "severity": "medium", "package": 7},
    {"ecosystem": "go", "package": "github.com/acme/mod", "severity": "critical", "action": "block"},
    {"ecosystem": "gemini", "name": "my-ext", "severity": "medium", "package": True},
    {"artifact_id": "install:custom:nomatch", "severity": "critical"},
    {"ecosystem": "pip", "package": "", "name": "black", "severity": 3},
    {"aliases": "lodash", "severity": "high"},
    {"package": "@scope/pkg", "severity": "high", "headline": "Scoped."},
    {"ecosystem": "claude-code", "name": "fs", "severity": "low", "action": "block"},
    {"artifact_id": "install:antigravity:mcp:ag", "severity": "low"},
    {"ecosystem": "npm", "package_url": "pkg:npm/typescript", "severity": "medium"},
]


def _rows(advisories: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {"cache_key": f"key-{index}", "updated_at": f"2026-10-{index + 1:02d}T00:00:00Z", **advisory}
        for index, advisory in enumerate(advisories)
    ]


ADVISORY_SETS: list[list[dict[str, object]]] = [
    [],
    _rows(BASE_ADVISORIES),
    _rows(list(reversed(BASE_ADVISORIES))),
]


def _record(name: str, command: list[str], advisories: list[dict[str, object]]) -> dict[str, object]:
    vector: dict[str, object] = {"name": name, "command": command, "advisories": advisories}
    try:
        request = parse_protect_command(command)
    except ValueError as error:
        vector["error"] = f"invalid_url:{error}"
        return vector
    verdict = evaluate_protect_request(request, advisories)
    positions = {str(advisory["cache_key"]): index for index, advisory in enumerate(advisories)}
    vector["request"] = request.to_dict()
    vector["verdict"] = {
        "action": verdict.action,
        "reason": verdict.reason,
        "risk_signals": list(verdict.risk_signals),
        "matched": [positions[str(item["cache_key"])] for item in verdict.matched_advisories],
    }
    return vector


def _require_reference_implementation() -> None:
    parameters = list(inspect.signature(evaluate_protect_request).parameters)
    if parameters[1:2] != ["advisories"]:
        raise SystemExit(
            "protect.py no longer has the Python reference implementation; "
            "run this script from a checkout that predates the native protect request op"
        )


def main() -> int:
    _require_reference_implementation()
    vectors: list[dict[str, object]] = []
    commands = PACKAGE_COMMANDS + REGISTRATION_COMMANDS + CUSTOM_COMMANDS + INVALID_URL_COMMANDS
    for (index, command), (set_index, advisories) in itertools.product(enumerate(commands), enumerate(ADVISORY_SETS)):
        vectors.append(_record(f"cmd{index}-adv{set_index}", command, advisories))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(gzip.compress(json.dumps(vectors, sort_keys=True).encode("utf-8"), mtime=0))
    print(f"wrote {len(vectors)} vectors to {OUT}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
