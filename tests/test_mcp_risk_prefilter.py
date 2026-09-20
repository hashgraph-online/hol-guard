"""Necessary-condition shortcuts preserve risk, policy and approval identities."""

from __future__ import annotations

import random
import re
from dataclasses import asdict
from ipaddress import IPv4Address, IPv6Address, ip_address

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.config import GuardConfig


def _unfiltered_matches(value, patterns):
    return any(
        re.search(pattern.expression if isinstance(pattern, calls._LiteralRiskPattern) else pattern, value) is not None
        for pattern in patterns
    )


def _unfiltered_ip(value):
    for match in re.finditer(r"(?<![0-9a-z])\[?([0-9a-f:.]{3,})\]?(?![0-9a-z])", value, flags=re.IGNORECASE):
        candidate = match.group(1)
        if candidate.count(":") == 1 and "." in candidate:
            candidate = candidate.partition(":")[0]
        try:
            ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def _unfiltered_camel(value):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)


def test_literal_prefilter_uses_the_same_alternatives_as_its_regex():
    tokens = ("spawn", "os.system", "port-forward", "id_rsa", "curl")
    rng = random.Random(19)
    corpus = ["", "lowercase words", "X" * 131072, "text: " + "x" * 131072]
    for token in tokens:
        for before in ("", "x", "1", "_", "-", ".", " ", "["):
            for after in ("", "x", "1", "_", "-", ".", " ", "()", "_sync()"):
                corpus.append(before + token + after)
    corpus.extend("".join(rng.choices("aA_-.()123 ", k=100)) for _ in range(200))
    for pattern in (
        calls._literal_pattern(*tokens, prefix=r"(?<![a-z0-9_])", suffix=r"(?:_sync)?\s*\("),
        calls._token_pattern(*tokens),
        calls._literal_pattern("http://", "https://"),
        calls._literal_pattern(),
        calls._token_pattern(""),
    ):
        for text in corpus:
            assert calls._matches_any(text, (pattern,)) == _unfiltered_matches(text, (pattern,))


def test_expanded_literal_alternatives_preserve_previous_regexes():
    # These optional alternatives changed spelling when literal lists became
    # the single source of truth; compare against their previous expressions.
    pairs = (
        (r"https?://", calls._literal_pattern("http://", "https://")),
        (
            r"(?<![a-z0-9_])(?:urllib(?:\.request)?|http\.client|https?)\s*\.",
            calls._literal_pattern(
                "urllib.request",
                "urllib",
                "http.client",
                "http",
                "https",
                prefix=r"(?<![a-z0-9_])",
                suffix=r"\s*\.",
            ),
        ),
        (
            r"(?<![a-z0-9])(id[_-]?rsa|credentials|token|secret|passwd)(?![a-z0-9])",
            calls._token_pattern("idrsa", "id_rsa", "id-rsa", "credentials", "token", "secret", "passwd"),
        ),
        (
            r"(?<![a-z0-9_-])\.(npmrc|pypirc)(?![a-z0-9_-])",
            calls._literal_pattern(".npmrc", ".pypirc", prefix=r"(?<![a-z0-9_-])", suffix=r"(?![a-z0-9_-])"),
        ),
    )
    probes = (
        "http://",
        "https://",
        "http",
        "https",
        "urllib",
        "urllib.request",
        "http.client",
        "idrsa",
        "id_rsa",
        "id-rsa",
        "credentials",
        "token",
        "secret",
        "passwd",
        ".npmrc",
        ".pypirc",
    )
    for previous, current in pairs:
        for token in probes:
            for before in ("", "x", "1", "_", "-", ".", " ", "["):
                for after in ("", "x", "1", "_", "-", ".", " .", "\t.", "\n.", "_sync()"):
                    text = before + token + after
                    assert (re.search(previous, text) is not None) == calls._matches_any(text, (current,))


def test_ip_shape_prefilter_matches_exact_previous_validator():
    rng = random.Random(37)
    addresses = ["::", "::1", "0:0:0:0:0:0:0:1", "::ffff:192.0.2.1", "fe80::1%fixture", "192.0.2.1:8080"]
    for _ in range(100):
        v6 = IPv6Address(rng.getrandbits(128))
        addresses.extend((str(IPv4Address(rng.getrandbits(32))), str(v6), v6.exploded))
    addresses.extend(("123", "0x1234", "abcd", "1:2:3", "1:2:3:4:5:6:7", "999.999.999.999", "x" * 131072))
    for address in addresses:
        for text in (address, f"[ {address} ]", f"prefix{address}suffix", f'synthetic:echo {{"value":"{address}"}}'):
            assert calls._contains_ip_address(text) == _unfiltered_ip(text)


@pytest.mark.parametrize(
    "text",
    ["", "123", "camelCase", "HTTPGet", "lowerCaseURL", "lower-words", "éÉ Σσ ıİ", "x" * 131072],
    ids=["empty", "digits", "camel", "acronym", "mixed-url", "lower-words", "unicode", "long-lowercase"],
)
def test_lowercase_shortcut_preserves_camel_normalization(text):
    assert calls._camel_token_normalized(text) == _unfiltered_camel(text)


@pytest.mark.parametrize("default_action", ["allow", "warn", "review", "block"])
def test_large_and_adversarial_facts_keep_policy_and_approval_hashes(tmp_path, monkeypatch, default_action):
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path, default_action=default_action)
    probes = [
        "x" * 131072,
        "ordinary text",
        "subprocess.run() child_process.spawn() childprocess popen os.system runtime.exec",
        "spawn_sync() execfile() system()",
        "https://example.invalid curl wget fetch axios requests socket.connect net.connect dns.resolve",
        "create_connection() getaddrinfo() gethostbyname() sendto() recvfrom()",
        "urllib.request.urlopen http.client. https. udp tcp socks proxy tunnel port_forward port-forward",
        ".env .ssh idrsa id_rsa id-rsa credentials token secret passwd .npmrc .pypirc",
        "sudo chmod chown launchctl systemctl",
        "prefixcurlprefix _token_ .env_example httpClient.get runtimeExec",
        "[2001:db8:0:0:0:0:0:1] [::1] 192.0.2.4:1234",
    ]
    for name, schema in (
        ("echo_0", {"type": "object", "properties": {"text": {"type": "string"}}}),
        ("summarize", {"type": "object", "properties": {"command": {"type": "string"}}}),
        ("browser_navigate", {"type": "object", "properties": {"url": {"type": "string"}}}),
    ):
        artifact = calls.build_tool_call_artifact(
            harness="codex",
            server_name="synthetic",
            tool_name=name,
            source_scope="project",
            config_path=".mcp.json",
            transport="stdio",
            tool_schema=schema,
            tool_description="Echo text.",
        )
        for text in probes:
            arguments = {"text": text, "sample": 17}

            def result(artifact=artifact, arguments=arguments):
                return {
                    "categories": calls.tool_call_risk_categories(artifact, arguments),
                    "hash": calls.build_tool_call_hash(artifact, arguments, workspace=tmp_path, config=config),
                    "decision": asdict(
                        calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments)
                    ),
                }

            optimized = result()
            with monkeypatch.context() as reference:
                reference.setattr(calls, "_matches_any", _unfiltered_matches)
                reference.setattr(calls, "_contains_ip_address", _unfiltered_ip)
                reference.setattr(calls, "_camel_token_normalized", _unfiltered_camel)
                assert result() == optimized
