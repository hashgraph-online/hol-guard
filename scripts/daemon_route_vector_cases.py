"""Route, origin, loopback and resolve cases for the daemon route vector recorder."""

from __future__ import annotations

import ast
from pathlib import Path

ORIGINS = [
    "http://127.0.0.1:4781",
    "http://localhost",
    "http://localhost:3000",
    "http://[::1]:5000",
    "http://LOCALHOST:3000",
    "http://127.0.0.2",
    "http://0.0.0.0",
    "https://hol.org",
    "https://www.hol.org",
    "https://hol.org/",
    "https://hol.org:443",
    "http://hol.org",
    "https://hol.org:8443",
    "HTTPS://HOL.ORG",
    "https://evil.com",
    "https://hol.org.evil.com",
    "https://sub.hol.org",
    "https://user@hol.org",
    "https://hol.org/path",
    "https://hol.org?x=1",
    "https://hol.org#f",
    "ftp://hol.org",
    "null",
    "",
    "   ",
    "https://[::1]",
    "https://localhost",
    "http://localhost.evil.com",
    "  https://www.hol.org  ",
    "http://127.0.0.1:99999",
    "http://127.0.0.1:0",
    "http://[::1]:5000/",
    "http://127.0.0.1:4781/x",
    "http://127.0.0.1:04781",
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "https://hol.org;x",
    "https://hol.org:abc",
]
ORIGIN_PATHS = [
    "/v1/runtime",
    "/v1/capabilities",
    "/v1/approvals/a1/decision",
    "/v1/extension-controls/inspect",
    "/v1/requests",
    "/v1/hooks/codex/pre",
    "/v1/local-clis/apply",
    "/v1/receipts/abc",
    "/",
]
LOOPBACK = [
    "http://127.0.0.1:4781",
    "http://127.0.0.1:4781/",
    "http://[::1]:4781",
    "http://[::1]:4781/",
    "  http://127.0.0.1:1 ",
    "http://127.0.0.1:65535",
    "http://127.0.0.1:65536",
    "http://127.0.0.1:0",
    "http://127.0.0.1",
    "http://localhost:4781",
    "https://127.0.0.1:4781",
    "http://127.0.0.1:4781/path",
    "http://127.0.0.1:04781",
    "http://0:4781",
    "HTTP://127.0.0.1:4781",
    "http://127.0.0.1.:4781",
    "http://user@127.0.0.1:4781",
    "http://[::ffff:127.0.0.1]:4781",
    "http://[0:0:0:0:0:0:0:1]:4781",
    "",
    "http://",
    "127.0.0.1:4781",
    "http://127.0.0.1:4781?x",
    "http://127.0.0.1:abc",
]


def _literal_paths(base_server: Path) -> list[str]:
    tree = ast.parse(base_server.read_text(encoding="utf-8"))
    found = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(("/v1/", "/v2/"))
        and " " not in node.value
        and "?" not in node.value
    }
    return sorted(found)


def route_paths(base_server: Path) -> list[str]:
    extra = [
        "/",
        "/v1",
        "/v1/hooks",
        "/v1/hooks/codex",
        "/v1/hooks/codex/pre",
        "/v1/hooks/claude/post/x",
        "/v1/apps",
        "/v1/apps/connect",
        "/v1/apps/repair",
        "/v1/apps/disconnect",
        "/v1/apps/status",
        "/v1/apps/test",
        "/v1/apps/bogus",
        "/v1/apps/connect/extra",
        "/v1/apps/cloud/start",
        "/v1/apps/codex/cloud/start",
        "/v1/apps/codex/cloud/stop",
        "/v1/requests/r1/approve",
        "/v1/requests/r1/block",
        "/v1/requests/r1/resume",
        "/v1/requests/r1/live-decision",
        "/v1/requests/r1/other",
        "/v1/requests/r1/business-summary",
        "/v1/requests/r1",
        "/v1/receipts/r1",
        "/v1/receipts/r1/x",
        "/v1/operations/o1/items",
        "/v1/operations/o1/status",
        "/v1/operations/o1",
        "/v1/operations/o1/other",
        "/v1/sessions/s1/resume",
        "/v1/mcp-policy/requests/r/decision",
        "/v1/mcp-policy/requests/r",
        "/v1/mcp-policy/requests/r/other",
        "/v1/mcp-policy/requests/r/decision/x",
        "/approvals/a1/decision",
        "/approvals/a1/other",
        "/v1/approvals/a1/decision",
        "/v1/approvals/a1/other",
        "/v1/audit/remediations/x",
        "/v1/audit/remediations",
        "/v1/audit/remediations/x/y",
        "/v1/harnesses/codex/install",
        "/v1/harnesses/codex/verify",
        "/v1/harnesses/codex/repair",
        "/v1/harnesses/codex/uninstall",
        "/v1/harnesses/codex/remove",
        "/v1/artifacts/a/diff",
        "/v1/artifacts/a/other",
        "/v2/extension-controls/catalog",
        "/v2/extension-controls/catalog/x",
        "/v2/extension-controls/catalog/x/y",
        "/v2/extension-controls/other",
        "/v1/supply-chain",
        "/v1/supply-chain/x",
        "/v1/supply-chain/x/y/z",
        "//v1//runtime",
        "/v1/runtime/",
        "/v1/runtime//",
        "/V1/runtime",
        "/v1/extension-controls/inspect",
        "/v1/extension-controls/preview",
    ]
    return sorted({*_literal_paths(base_server), *extra})


# The retired handler used ``str.isdigit()`` on the version suffix, which also
# accepts non-ASCII digits. The resident accepts ASCII digits only, on purpose:
# a contract version is machine-readable input and a look-alike digit must not
# match. ``record_daemon_route_vectors.py`` records these as deliberate
# rejections instead of the retired Python answer.
NARROWED_VERSION_SUFFIXES = ("guard.approval-scopes.v\u0667", "guard.approval-scopes.v\u00b2")


def resolve_cases() -> list[dict]:
    paths = [
        "/v1/requests/r1/approve",
        "/v1/requests/r1/block",
        "/approvals/a1/decision",
        "/v1/approvals/a2/decision",
        "/v1/requests/r1/resume",
        "/v1/requests/r1/other",
        "/",
        "/v1/approvals/a1/decision/x",
        "/approvals/a1/other",
    ]
    valid = {
        "action": "allow",
        "scope": "artifact",
        "scope_contract_version": "guard.approval-scopes.v7",
        "scope_contract_digest": "a" * 64,
    }
    variations: dict[str, list[object]] = {
        "action": ["allow", "block", "  allow ", "", "   ", 5, None, ["a"]],
        "scope": ["artifact", "  workspace  ", "", "   ", 5, None],
        "scope_contract_version": [
            None,
            "",
            "  ",
            "guard.approval-scopes.v7",
            " guard.approval-scopes.v7 ",
            "guard.approval-scopes.v",
            "guard.approval-scopes.vx",
            "guard.approval-scopes.v07",
            "guard.approval-scopes.v7.1",
            "other.v7",
            "guard.approval-scopes.v-1",
            "guard.approval-scopes.v 7",
            7,
            True,
            "guard.approval-scopes.v12345678901234567890",
            *NARROWED_VERSION_SUFFIXES,
        ],
        "scope_contract_digest": [
            None,
            "a" * 64,
            "A" * 64,
            "a" * 63,
            "a" * 65,
            "",
            "   ",
            f" {'b' * 64} ",
            "g" * 64,
            5,
            "0123456789abcdef" * 4,
            "0123456789abcdeg" * 4,
        ],
    }
    cases = []
    for path in paths:
        if path not in paths[:4]:
            cases.append(
                {
                    "kind": "resolve_request",
                    "name": f"resolve.valid.{path}",
                    "raw": {"path": path, "payload": dict(valid)},
                }
            )
            continue
        for field, values in variations.items():
            for index, value in enumerate(values):
                payload = dict(valid)
                if value is None and field in ("action", "scope"):
                    payload.pop(field)
                else:
                    payload[field] = value
                cases.append(
                    {
                        "kind": "resolve_request",
                        "name": f"resolve.{path}.{field}.{index}",
                        "raw": {"path": path, "payload": payload},
                    }
                )
    for combo, payload in {
        "all_missing": {},
        "bad_version_and_digest": {**valid, "scope_contract_version": "x", "scope_contract_digest": "y"},
        "missing_scope_bad_version": {"action": "allow", "scope_contract_version": "x"},
        "missing_action_bad_digest": {"scope": "s", "scope_contract_digest": "y"},
        "no_optional_fields": {"action": "allow", "scope": "s"},
    }.items():
        for path in paths[:4]:
            cases.append(
                {
                    "kind": "resolve_request",
                    "name": f"resolve.combo.{combo}.{path}",
                    "raw": {"path": path, "payload": payload},
                }
            )
    return cases
