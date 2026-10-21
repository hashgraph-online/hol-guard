"""Regenerate the artifact-hash parity corpus.

``consumer/service.artifact_hash`` names the bytes a saved approval is bound
to, so the native implementation has to reproduce CPython's answer exactly,
including the redaction ``GuardArtifact.to_dict`` applies on the way. This
script records the Python answer for a corpus that exercises each branch of
that shaping, and the Rust test asserts its own answer matches.

Run it from the repository root after changing either side:

    python scripts/ci/generate_artifact_hash_parity.py [output-path]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from codex_plugin_scanner.guard.consumer.service import artifact_hash
from codex_plugin_scanner.guard.models import GuardArtifact

FIXTURE = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/artifact-hash-parity.v1.json")

# Every case names the shaping branch it covers, so a future change to the
# redaction or payload rules fails on the case whose rule moved.
CASES: list[dict[str, Any]] = [
    {
        "case": "plain_hook",
        "covers": "the default payload: no codex identity, no prompt redaction",
        "artifact": {
            "artifact_id": "claude-code:hook:PreToolUse",
            "name": "pre tool hook",
            "harness": "claude-code",
            "artifact_type": "hook",
            "source_scope": "harness",
            "config_path": "/home/u/.claude/settings.json",
        },
    },
    {
        "case": "codex_hook_identity",
        "covers": "the codex-hook short payload, which ignores every other field",
        "artifact": {
            "artifact_id": "codex:hook:exec",
            "name": "exec hook",
            "harness": "codex",
            "artifact_type": "hook",
            "source_scope": "harness",
            "config_path": "/home/u/.codex/config.toml",
            "metadata": {"codex_hook_identity": "exec:v1", "ignored": "by the short payload"},
        },
    },
    {
        "case": "codex_hook_identity_blank",
        "covers": "a blank identity falling back to the default payload",
        "artifact": {
            "artifact_id": "codex:hook:exec",
            "name": "exec hook",
            "harness": "codex",
            "artifact_type": "hook",
            "source_scope": "harness",
            "config_path": "/home/u/.codex/config.toml",
            "metadata": {"codex_hook_identity": ""},
        },
    },
    {
        "case": "prompt_request_volatile_metadata",
        "covers": "prompt_request dropping the volatile keys and keeping the intent hash",
        "artifact": {
            "artifact_id": "claude-code:native-prompt:session",
            "name": "user prompt",
            "harness": "claude-code",
            "artifact_type": "prompt_request",
            "source_scope": "harness",
            "config_path": "",
            "metadata": {
                "normalized_path": "/w/notes.md",
                "prompt_intent_hash": "  abc123  ",
                "prompt_request_classes": ["secret_read"],
            },
        },
    },
    {
        "case": "prompt_request_without_normalized_path",
        "covers": "prompt_request keeping its metadata when no path was normalized",
        "artifact": {
            "artifact_id": "claude-code:native-prompt:session",
            "name": "user prompt",
            "harness": "claude-code",
            "artifact_type": "prompt_request",
            "source_scope": "harness",
            "config_path": "",
            "metadata": {"prompt_request_classes": ["local_env_read"]},
        },
    },
    {
        "case": "redacted_url_query",
        "covers": "url query redaction and its re-encoding",
        "artifact": {
            "artifact_id": "mcp:server:remote",
            "name": "remote server",
            "harness": "claude-code",
            "artifact_type": "mcp_server",
            "source_scope": "project",
            "config_path": "/w/.mcp.json",
            "url": "https://example.test/sse?api_key=live-secret&page=2&Token=x y&plain=keep",
            "transport": "sse",
        },
    },
    {
        "case": "url_without_query",
        "covers": "a url with no query returning unchanged",
        "artifact": {
            "artifact_id": "mcp:server:remote",
            "name": "remote server",
            "harness": "claude-code",
            "artifact_type": "mcp_server",
            "source_scope": "project",
            "config_path": "/w/.mcp.json",
            "url": "https://example.test/sse#frag",
        },
    },
    {
        "case": "redacted_args",
        "covers": "header-style and query-style argument redaction",
        "artifact": {
            "artifact_id": "mcp:server:local",
            "name": "local server",
            "harness": "codex",
            "artifact_type": "mcp_server",
            "source_scope": "user",
            "config_path": "/w/.mcp.json",
            "command": "npx",
            "args": [
                "--header",
                "Authorization: Bearer live-secret",
                "API-Key: live",
                "--url=https://example.test?token=live",
                "token=live",
                "--keep=1",
            ],
        },
    },
    {
        "case": "redacted_metadata_tree",
        "covers": "env masking, secret-keyed values and recursion through lists",
        "artifact": {
            "artifact_id": "mcp:server:env",
            "name": "env server",
            "harness": "codex",
            "artifact_type": "mcp_server",
            "source_scope": "user",
            "config_path": "/w/.mcp.json",
            "metadata": {
                "env": {"OPENAI_API_KEY": "live", "PATH": "/usr/bin"},
                "environment": {"X": "live"},
                "auth_token": "live",
                "nested": [{"password": "live"}, {"plain": "keep"}],
                "env_keys": ["OPENAI_API_KEY", "PATH"],
                "count": 3,
            },
        },
    },
    {
        "case": "prompt_request_redacted_env_keys",
        "covers": "env_keys surviving as the masked string the redaction left behind",
        "artifact": {
            "artifact_id": "claude-code:native-prompt:session",
            "name": "user prompt",
            "harness": "claude-code",
            "artifact_type": "prompt_request",
            "source_scope": "harness",
            "config_path": "",
            "metadata": {
                "normalized_path": "/w/.env",
                "env_keys": ["OPENAI_API_KEY"],
                "prompt_display_text": "dropped",
                "request_summary": "dropped",
            },
        },
    },
    {
        "case": "prompt_request_blank_intent_hash",
        "covers": "a whitespace-only intent hash keeping the unredacted value",
        "artifact": {
            "artifact_id": "claude-code:native-prompt:session",
            "name": "user prompt",
            "harness": "claude-code",
            "artifact_type": "prompt_request",
            "source_scope": "harness",
            "config_path": "",
            "metadata": {"normalized_path": "/w/notes.md", "prompt_intent_hash": "   "},
        },
    },
    {
        "case": "metadata_without_env_keys",
        "covers": "the env_keys mirror defaulting to an empty list",
        "artifact": {
            "artifact_id": "mcp:server:bare",
            "name": "bare server",
            "harness": "codex",
            "artifact_type": "mcp_server",
            "source_scope": "user",
            "config_path": "/w/.mcp.json",
            "metadata": {"count": 1},
            "publisher": "example",
            "transport": "stdio",
        },
    },
    {
        "case": "non_ascii_and_floats",
        "covers": "the ASCII escaping and float spelling the encoder has to match",
        "artifact": {
            "artifact_id": "codex:hook:café",
            "name": "naïve \U0001f600 hook",
            "harness": "codex",
            "artifact_type": "hook",
            "source_scope": "harness",
            "config_path": "/w/ünïcode.toml",
            "metadata": {"ratio": 0.1, "whole": 2.0, "big": 1e22, "小": "値"},
        },
    },
]


# `_redact_url` round-trips every url that carries a query through
# ``urlsplit``/``parse_qsl``/``urlencode``/``urlunsplit``, so the re-encoding
# rewrites the query even where nothing was secret. These urls pin that
# rewriting, the inputs ``urlsplit`` rejects, and the decode of a broken
# escape; each becomes one case named after the shape it covers.
URLS: list[tuple[str, str]] = [
    ("plus_and_percent", "https://example.test/p?q=a+b%20c&r=%2Fslash%3Acolon"),
    ("blank_and_bare_keys", "https://example.test/p?a=&b&c=1"),
    ("empty_and_repeated_separators", "https://example.test/p?&&a=1&&"),
    ("repeated_keys", "https://example.test/p?a=1&a=2&A=3"),
    ("unreserved_round_trip", "https://example.test/p?k=-_.~abcZ09"),
    ("reserved_needs_encoding", "https://example.test/p?k=a/b:c@d,e;f!g*h'i(j)"),
    ("raw_non_ascii_query", "https://example.test/p?q=caf\u00e9&\u5c0f=\u5024"),
    ("percent_encoded_non_ascii", "https://example.test/p?q=caf%C3%A9"),
    ("invalid_percent_escape", "https://example.test/p?q=%zz%4&r=%"),
    ("invalid_utf8_escape", "https://example.test/p?q=%e0%80%41"),
    ("mixed_case_secret_keys", "https://example.test/p?AUTHORIZATION=x&Api_Token=y&monkey=z"),
    ("secret_substring_key", "https://example.test/p?keyboard=1&tokenizer=2"),
    ("fragment_after_query", "https://example.test/p?a=1#frag?b=2"),
    ("uppercase_scheme", "HTTPS://Example.Test/P?a=1"),
    ("scheme_relative", "//example.test/p?a=1"),
    ("path_only", "p/q?a=1"),
    ("netloc_absent_uses_netloc_scheme", "https:?a=1"),
    ("unknown_scheme", "custom:opaque?a=1"),
    ("userinfo_and_port", "https://user:pw@example.test:8443/p?a=1"),
    ("ipv6_host", "http://[::1]:8080/p?a=1"),
    ("ipv6_zone", "http://[fe80::1%25eth0]/p?a=1"),
    ("ipv_future_host", "http://[v7.plan9]/p?a=1"),
    ("unterminated_ipv6_is_unchanged", "http://[::1/p?a=1"),
    ("ipv4_in_brackets_is_unchanged", "http://[127.0.0.1]/p?a=1"),
    ("data_before_bracket_is_unchanged", "http://a[::1]/p?token=x"),
    ("data_after_bracket_is_unchanged", "http://[::1]x/p?token=x"),
    ("bracketed_userinfo_before_ipv6_host", "http://u[x]@[::1]/p?token=x"),
    ("bracketed_userinfo_before_named_host_is_unchanged", "http://u[x]@example.test/p?token=x"),
    ("empty_authority_double_slash_path", "https:////example.test/p?token=abc"),
    ("nfkc_netloc_is_unchanged", "http://example\u2100com/p?a=1"),
    ("leading_control_and_inner_tabs", "  \x01https://exa\tmple.test/p?a=\n1"),
    ("empty_query_marker", "https://example.test/p?"),
    ("query_only", "?token=live"),
]

# `_redact_arg` matches on the lowercased argument but rebuilds the masked
# value from the original, so case and the position of the first delimiter
# both matter.
ARG_SETS: list[tuple[str, list[str]]] = [
    ("header_case_insensitive", ["authorization: Bearer x", "X-API-Key: live", "AUTHORIZATION:x"]),
    ("bearer_without_colon", ["Bearer live-secret"]),
    ("query_style_variants", ["apikey=1", "API_KEY=2", "--api-key=3", "a=b&token=c", "secret=d"]),
    ("colon_before_equals", ["https://u:p@h/x?token=1"]),
    ("no_delimiter_match", ["--plain", "value", "", "token", "key="]),
]


def main() -> int:
    specs = list(CASES)
    for name, url in URLS:
        specs.append(
            {
                "case": f"url_{name}",
                "covers": f"url redaction round-tripping {name.replace('_', ' ')}",
                "artifact": {
                    "artifact_id": f"mcp:server:{name}",
                    "name": "remote server",
                    "harness": "claude-code",
                    "artifact_type": "mcp_server",
                    "source_scope": "project",
                    "config_path": "/w/.mcp.json",
                    "url": url,
                },
            }
        )
    for name, args in ARG_SETS:
        specs.append(
            {
                "case": f"args_{name}",
                "covers": f"argument redaction for {name.replace('_', ' ')}",
                "artifact": {
                    "artifact_id": f"mcp:server:{name}",
                    "name": "local server",
                    "harness": "codex",
                    "artifact_type": "mcp_server",
                    "source_scope": "user",
                    "config_path": "/w/.mcp.json",
                    "command": "npx",
                    "args": args,
                },
            }
        )

    cases = []
    for case in specs:
        fields = dict(case["artifact"])
        fields["args"] = tuple(fields.get("args", ()))
        artifact = GuardArtifact(**fields)
        cases.append(
            {
                "case": case["case"],
                "covers": case["covers"],
                "artifact": case["artifact"],
                "expected_sha256": artifact_hash(artifact),
            }
        )
    FIXTURE.write_text(
        json.dumps(
            {
                "schema": "artifact-hash-parity.v1",
                "generator": "scripts/ci/generate_artifact_hash_parity.py",
                "cases": cases,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(cases)} cases to {FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
