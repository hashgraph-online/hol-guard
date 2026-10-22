r"""Record the inventory serializer-redaction corpus the Rust port must match.

`inventory_contract_redaction` guards every exported inventory payload. Three
CPython behaviours decide its output and none of them is the Rust default:

1. `json.dumps(payload, sort_keys=True)` writes `", "` and `": "` separators
   and escapes every non-ASCII character, so the text the safety assertion
   scans is not `serde_json::to_string`.
2. `re` treats `\s`/`\S` as `Py_UNICODE_ISSPACE`, which includes U+001C..U+001F.
   `char::is_whitespace` follows Unicode `White_Space` and excludes them, so a
   `bearer\s+\S+` secret separated by U+001D is caught in Python and missed by
   a naive port.
3. `isinstance(candidate, int)` accepts `bool`, and `str(True)` is `"True"`,
   so a `totalFindings` of `true` reaches the exported detail as text.

Run this after changing the redaction module and commit the regenerated
fixture; `inventory_redaction_tests.rs` reads it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.inventory_contract_redaction import (
    _assert_serialized_inventory_payload_safe,
    _safe_json,
    _safe_source_detail,
    _sanitize_serializer_string,
)

FIXTURE = Path("rust/crates/guard-command/testdata/inventory_redaction_parity.json")


class _Run:
    """Duck-typed stand-in for the sync-run objects `_safe_source_detail` reads."""

    def __init__(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            setattr(self, key, value)


SANITIZE_CASES: list[tuple[str, str, bool]] = [
    ("plain value", "", False),
    ("[REDACTED]", "token", True),
    ("present", "authorization", False),
    ("present_redacted", "", True),
    ("redacted", "secret", True),
    ("malformed_url_redacted", "password", True),
    ("harmless", "api_key", False),
    ("harmless", "apiKey", False),
    ("harmless", "API-KEY", False),
    ("harmless", "apixkey", False),
    ("harmless", "credential_id", False),
    ("harmless", "bearerish", False),
    ("harmless", "name", True),
    ("harmless", "name", False),
    ("/Users/someone/project", "", False),
    ("value=/home/someone/x", "", False),
    ("prefix/Users/someone", "", False),
    ("(/tmp/thing)", "", False),
    ("{/etc/hosts", "", False),
    ("C:\\Users\\someone", "", False),
    ("a\\Users\\someone", "", False),
    ("/var/folders/ab/cd", "", False),
    ("see /mnt/data/file", "", False),
    ("/workspace/app", "", False),
    ("/usr/local/bin", "", False),
    ("ghp_abcdef0123456789", "", False),
    ("ghs_ABCDEF", "", False),
    ("ghx_abcdef", "", False),
    ("sk-abc-def_123", "", False),
    ("guard_live_abc-123", "", False),
    ("bearer abc.def", "", False),
    ("Bearer\tabc", "", False),
    ("bearer\u001dabc", "", False),
    ("bearer\u00a0abc", "", False),
    ("bearer", "", False),
    ("token = supersecret", "", False),
    ("token: redacted", "", False),
    ("token: redactedly", "", False),
    ("api-key=abc", "", False),
    ("access_token:abc", "", False),
    ("refresh-token = abc", "", False),
    ("mytoken: abc", "", False),
    ("token:", "", False),
    ("token:\u001dabc", "", False),
    # CPython `re.IGNORECASE` folds U+0130/U+0131 onto `i`; Rust's simple case
    # folding does not, so these pin the key, value and assignment routes.
    ("harmless", "credent\u0131al", False),
    ("harmless", "credent\u0130al", False),
    ("harmless", "ap\u0131\u0131key", False),
    ("guard_l\u0131ve_abc", "", False),
    ("ap\u0131-key=abc", "", False),
    # CPython `\b` uses `str.isalnum()`; Rust's `\w` also counts combining
    # marks and connector punctuation, so a naive `\b` port fails open here.
    ("e\u0301token=abc", "", False),
    ("x\u203ftoken=abc", "", False),
    ("", "", False),
    ("", "token", False),
]

SAFE_JSON_VALUES: list[Any] = [
    "plain",
    "/Users/someone",
    123,
    12.5,
    True,
    None,
    [],
    {},
    ["plain", "/tmp/x", 7],
    {"token": "abc"},
    {"token": {"nested": "abc", "count": 3}},
    {"credent\u0131al": "abc"},
    {"safe": "guard_l\u0131ve_abc"},
    {"outer": {"token": "abc", "safe": "ok"}},
    {"safe": ["ghp_abcdef", {"deep": "bearer xyz"}]},
    {"authorization": ["abc", "def"]},
    {"/Users/someone": "value"},
    {"token": True},
    {"list": [["bearer abc"]]},
    {"present": "present", "redacted": "redacted"},
    {"a": {"b": {"c": "/etc/passwd"}}},
]

ASSERT_PAYLOADS: list[Any] = [
    {"ok": "value"},
    {"token": "redacted"},
    {"token": "abc"},
    {"path": "/Users/someone"},
    {"path": "/usr/share"},
    {"secret": "[REDACTED]"},
    {"value": "ghp_abcdef0123"},
    {"value": "bearer abc"},
    ["safe", "list"],
    ["/home/someone"],
    {"nested": {"deep": ["password = hunter2"]}},
    {"value": "guard_l\u0131ve_abc"},
    {"value": "e\u0301token=abc"},
    {"caf\u00e9": "value"},
    {"token": None},
    {"b": 1, "a": 2},
    "plain string payload",
]

SOURCE_DETAIL_RUNS: list[dict[str, Any]] = [
    {"status": "ok", "metadata": {"totalFindings": 4}},
    {"status": "ok", "metadata": {"totalFindings": 0}},
    {"status": "failed", "metadata": {}},
    {"status": "failed", "metadata": {"totalFindings": "4"}},
    {"status": "failed", "metadata": {"totalFindings": 4.0}},
    {"status": "failed", "metadata": {"totalFindings": True}},
    {"status": "failed", "metadata": {"totalFindings": None}},
    {"status": "failed", "metadata": []},
    {"metadata": {"totalFindings": 2}},
    {"status": None, "metadata": {}},
    {"status": True, "metadata": {}},
    {"status": 7, "metadata": {}},
    {},
]

SORTED_JSON_VALUES: list[Any] = [
    {"b": 1, "a": 2},
    {"nested": {"z": [1, 2], "a": "x"}},
    ["a", 1, True, None],
    {"caf\u00e9": "na\u00efve"},
    {"astral": "\U0001f600"},
    {"control": "tab\there"},
    {"float": 1e17},
    {"float": 0.1},
    {"empty": {}, "list": []},
    "scalar",
]


def build_document() -> dict[str, Any]:
    """Collect every parity section from the real Python implementation."""
    sanitize = [
        {
            "value": value,
            "parent_key": parent_key,
            "parent_sensitive": parent_sensitive,
            "expected": _sanitize_serializer_string(
                value,
                parent_key=parent_key,
                parent_sensitive=parent_sensitive,
            ),
        }
        for value, parent_key, parent_sensitive in SANITIZE_CASES
    ]
    safe_json = [{"value": value, "expected": _safe_json(value)} for value in SAFE_JSON_VALUES]
    assertions = []
    for payload in ASSERT_PAYLOADS:
        try:
            _assert_serialized_inventory_payload_safe(payload)
        except ValueError:
            safe = False
        else:
            safe = True
        assertions.append({"payload": payload, "safe": safe})
    source_detail = [{"run": run, "expected": _safe_source_detail(_Run(run))} for run in SOURCE_DETAIL_RUNS]
    sorted_json = [{"value": value, "expected": json.dumps(value, sort_keys=True)} for value in SORTED_JSON_VALUES]
    return {
        "assert_payload_safe": assertions,
        "safe_json": safe_json,
        "safe_source_detail": source_detail,
        "sanitize_serializer_string": sanitize,
        "sorted_json": sorted_json,
    }


def main() -> None:
    """Write the parity fixture the Rust redaction tests read."""
    document = build_document()
    FIXTURE.write_text(
        json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
