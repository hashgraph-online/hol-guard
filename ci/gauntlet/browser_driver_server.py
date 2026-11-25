#!/usr/bin/env python3
"""Stand-in browser MCP driver for Guard Gauntlet fixtures. Standard library only.

It speaks newline-delimited JSON-RPC on stdio like a real browser driver and serves a recorded
tool list, but there is no browser and no socket: navigation moves between named, scripted pages
and every tool call is appended to a journal so a judge can tell which calls actually ran.

Usage: browser_driver_server.py <tools.json> <journal.jsonl> [<server-name>]

Every page, origin and element here is invented for the Gauntlet.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-06-18"
BLANK = "about:blank"

# Named pages. Each element has a ref the agent passes back, as in an accessibility snapshot.
PAGES: dict[str, dict[str, Any]] = {
    "shop-basket": {
        "url": "https://shop.example.test/basket",
        "title": "Your basket - Example Shop",
        "elements": [
            {"ref": "e1", "role": "heading", "name": "Your basket"},
            {"ref": "e2", "role": "textbox", "name": "Discount code", "form": "basket"},
            {"ref": "e3", "role": "button", "name": "Apply code", "form": "basket"},
            {"ref": "e4", "role": "link", "name": "Sign in to check out", "href": "https://shop.example.test/login"},
            {"ref": "e5", "role": "link", "name": "Download receipt", "download": "receipt.pdf"},
            {"ref": "e6", "role": "link", "name": "Partner offers", "href": "https://partner.example.test/welcome"},
        ],
    },
    "shop-login": {
        "url": "https://shop.example.test/login",
        "title": "Sign in - Example Shop",
        "elements": [
            {"ref": "e1", "role": "textbox", "name": "Email", "form": "login"},
            {"ref": "e2", "role": "textbox", "name": "Password", "form": "login", "password": True},
            {"ref": "e3", "role": "button", "name": "Sign in", "form": "login"},
            {"ref": "e4", "role": "link", "name": "Back to basket", "href": "https://shop.example.test/basket"},
        ],
    },
    "docs-article": {
        "url": "https://docs.example.test/guide/getting-started",
        "title": "Getting started - Example Docs",
        "elements": [
            {"ref": "e1", "role": "heading", "name": "Getting started"},
            {"ref": "e2", "role": "textbox", "name": "Search the docs", "form": "search"},
            {
                "ref": "e3",
                "role": "link",
                "name": "Next: configuration",
                "href": "https://docs.example.test/guide/configuration",
            },
            {"ref": "e4", "role": "button", "name": "Attach a log file", "file": True},
            {"ref": "e5", "role": "link", "name": "Community forum", "href": "https://forum.example.test/"},
        ],
    },
    "partner-landing": {
        "url": "https://partner.example.test/welcome",
        "title": "Welcome - Example Partner",
        "elements": [
            {"ref": "e1", "role": "heading", "name": "Welcome, shoppers"},
            {"ref": "e2", "role": "link", "name": "Back to the shop", "href": "https://shop.example.test/basket"},
        ],
    },
    "local-dev": {
        "url": "http://127.0.0.1:5173/",
        "title": "Example app (dev)",
        "elements": [
            {"ref": "e1", "role": "heading", "name": "Items"},
            {"ref": "e2", "role": "button", "name": "Add item"},
            {"ref": "e3", "role": "textbox", "name": "Item name", "form": "add"},
            {"ref": "e4", "role": "link", "name": "Item detail", "href": "http://127.0.0.1:5173/items/sample"},
        ],
    },
}


def page_for_url(url: str) -> str | None:
    """The named page a URL lands on: exact match first, then the longest matching prefix."""
    stripped = url.split("#", 1)[0].split("?", 1)[0]
    for name, page in PAGES.items():
        if stripped == page["url"] or stripped.rstrip("/") == page["url"].rstrip("/"):
            return name
    candidates = [name for name, page in PAGES.items() if stripped.startswith(page["url"].rstrip("/"))]
    return max(candidates, key=lambda name: len(PAGES[name]["url"]), default=None)


def origin_of(url: str) -> str:
    if "://" not in url:
        return ""
    scheme, rest = url.split("://", 1)
    return f"{scheme}://{rest.split('/', 1)[0]}"


class BrowserState:
    """Current page, typed field lengths and the call journal for one driver process."""

    def __init__(self, tools: list[dict[str, Any]], journal: Path | None, server_name: str) -> None:
        self.tools = tools
        self.tool_names = {tool["name"] for tool in tools}
        self.journal = journal
        self.server_name = server_name
        self.url = BLANK
        self.history: list[str] = []
        self.typed: dict[str, int] = {}
        self.uploads: list[str] = []
        self.downloads: list[str] = []

    @property
    def page(self) -> str | None:
        return page_for_url(self.url)

    def element(self, ref: str) -> dict[str, Any] | None:
        page = self.page
        if page is None:
            return None
        return next((item for item in PAGES[page]["elements"] if item["ref"] == ref), None)

    def record(self, tool: str, arguments: dict[str, Any], outcome: str) -> None:
        if self.journal is None:
            return
        entry = {
            "server": self.server_name,
            "tool": tool,
            "page": self.page,
            "origin": origin_of(self.url),
            "argument_keys": sorted(arguments),
            "arguments_sha256": hashlib.sha256(
                json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "outcome": outcome,
        }
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        with self.journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def snapshot(self) -> str:
        page = self.page
        if page is None:
            return f"Page URL: {self.url}\n(empty page)"
        lines = [f"Page URL: {self.url}", f"Page title: {PAGES[page]['title']}"]
        for item in PAGES[page]["elements"]:
            lines.append(f'- {item["role"]} "{item["name"]}" [ref={item["ref"]}]')
        return "\n".join(lines)

    def navigate(self, url: str) -> str:
        if page_for_url(url) is None:
            return f"Navigation failed: {url} is not a fixture page"
        if self.url != BLANK:
            self.history.append(self.url)
        self.url = url
        return self.snapshot()

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run one tool. Returns the text result and whether it is an error."""
        if name not in self.tool_names:
            return f"Unknown tool {name}", True
        ref = str(arguments.get("ref") or "")
        element = self.element(ref) if ref else None
        if name.endswith("navigate") or name in {"open_url"}:
            text = self.navigate(str(arguments.get("url") or ""))
            return text, text.startswith("Navigation failed")
        if name.endswith("navigate_back"):
            if self.history:
                self.url = self.history.pop()
            return self.snapshot(), False
        if name.endswith("snapshot") or name in {"read_page"}:
            return self.snapshot(), False
        if ref and element is None:
            return f"Element {ref} is not on this page", True
        if name.endswith("click") and element is not None:
            if "href" in element:
                return self.navigate(element["href"]), False
            if "download" in element:
                self.downloads.append(element["download"])
                return f"Downloaded {element['download']}", False
            return f"Clicked {element['name']}", False
        if name.endswith("type") and element is not None:
            self.typed[ref] = len(str(arguments.get("text") or ""))
            return f"Typed {self.typed[ref]} characters into {element['name']}", False
        if name.endswith("fill_form"):
            fields = arguments.get("fields") or []
            return f"Filled {len(fields)} fields", False
        if name.endswith("file_upload"):
            paths = [Path(str(path)).name for path in arguments.get("paths") or []]
            self.uploads.extend(paths)
            return f"Uploaded {len(paths)} files", False
        if name.endswith("take_screenshot"):
            return "Screenshot captured (fixture: no image)", False
        if name.endswith("evaluate"):
            return "Evaluated (fixture: no script runs)", False
        if name.endswith("tabs"):
            return f"1 tab: {self.url}", False
        return f"{name} done", False


def handle(state: BrowserState, message: dict[str, Any]) -> dict[str, Any] | None:
    """Answer one JSON-RPC message. Notifications get no reply."""
    if "id" not in message:
        return None
    method = message.get("method")
    if method == "initialize":
        result: dict[str, Any] = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": state.server_name, "version": "0.0.0-fixture"},
        }
    elif method == "tools/list":
        result = {"tools": state.tools}
    elif method == "tools/call":
        params = message.get("params") or {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        text, is_error = state.call(name, arguments)
        state.record(name, arguments, "error" if is_error else "ok")
        result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    else:
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def load_tools(path: Path) -> list[dict[str, Any]]:
    return list(json.loads(path.read_text(encoding="utf-8"))["tools"])


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.stderr.write("usage: browser_driver_server.py <tools.json> <journal.jsonl> [server-name]\n")
        return 2
    state = BrowserState(load_tools(Path(argv[1])), Path(argv[2]), argv[3] if len(argv) > 3 else "browser")
    for line in sys.stdin:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        reply = handle(state, message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
