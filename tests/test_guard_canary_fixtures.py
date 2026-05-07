"""Tests verifying that canary fixture scripts contain only fake key material — T606."""

from __future__ import annotations

import ast
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "guard-red-team"
CANARY_SCRIPT = FIXTURES_DIR / "canary-exfil.py"
ENCODED_CANARY_SCRIPT = FIXTURES_DIR / "canary-exfil-encoded.py"

_REAL_KEY_PREFIXES = ("sk-", "ghp_", "ghs_", "glpat-", "xoxb-", "xoxp-", "AIza")
_ALLOWED_FAKE_PREFIX = "hol-fake-"
_CANARY_ENDPOINT = "https://evil.hol.org/collect"
_REAL_ENDPOINT_PATTERNS = ("openai.com", "api.github.com", "hooks.slack.com", "discord.com/api")


def _load_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_string_literals(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]


class TestCanaryExfilFixture:
    def test_canary_script_exists(self) -> None:
        assert CANARY_SCRIPT.exists(), f"Missing fixture: {CANARY_SCRIPT}"

    def test_only_fake_key_material(self) -> None:
        source = _load_source(CANARY_SCRIPT)
        for prefix in _REAL_KEY_PREFIXES:
            assert prefix not in source, (
                f"Canary script contains potentially real key prefix '{prefix}'. Use hol-fake-* sentinel values only."
            )

    def test_contains_fake_prefix(self) -> None:
        source = _load_source(CANARY_SCRIPT)
        assert _ALLOWED_FAKE_PREFIX in source, f"Canary script must contain fake key sentinel '{_ALLOWED_FAKE_PREFIX}'"

    def test_only_canary_endpoint(self) -> None:
        source = _load_source(CANARY_SCRIPT)
        assert _CANARY_ENDPOINT in source, "Canary script must target the canary endpoint"
        for real_endpoint in _REAL_ENDPOINT_PATTERNS:
            assert real_endpoint not in source, f"Canary script must not reference real endpoint '{real_endpoint}'"

    def test_canary_script_is_valid_python(self) -> None:
        source = _load_source(CANARY_SCRIPT)
        try:
            ast.parse(source)
        except SyntaxError as exc:
            raise AssertionError(f"Canary script has syntax error: {exc}") from exc

    def test_no_real_keys_in_string_literals(self) -> None:
        source = _load_source(CANARY_SCRIPT)
        for literal in _extract_string_literals(source):
            for prefix in _REAL_KEY_PREFIXES:
                assert not literal.startswith(prefix), (
                    f"String literal '{literal[:20]}...' looks like a real key (prefix '{prefix}')"
                )


class TestEncodedCanaryFixture:
    def test_encoded_canary_script_exists(self) -> None:
        assert ENCODED_CANARY_SCRIPT.exists(), f"Missing fixture: {ENCODED_CANARY_SCRIPT}"

    def test_only_fake_key_material(self) -> None:
        source = _load_source(ENCODED_CANARY_SCRIPT)
        for prefix in _REAL_KEY_PREFIXES:
            assert prefix not in source, (
                f"Encoded canary script contains potentially real key prefix '{prefix}'. "
                "Use hol-fake-* sentinel values only."
            )

    def test_contains_fake_prefix(self) -> None:
        source = _load_source(ENCODED_CANARY_SCRIPT)
        assert _ALLOWED_FAKE_PREFIX in source, (
            f"Encoded canary script must contain fake key sentinel '{_ALLOWED_FAKE_PREFIX}'"
        )

    def test_only_canary_endpoint_in_decoded_payload(self) -> None:
        import base64

        source = _load_source(ENCODED_CANARY_SCRIPT)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
                try:
                    decoded = base64.b64decode(node.value).decode("utf-8", errors="replace")
                    for real_endpoint in _REAL_ENDPOINT_PATTERNS:
                        assert real_endpoint not in decoded, (
                            f"Decoded payload references real endpoint '{real_endpoint}'"
                        )
                except Exception:
                    pass

    def test_encoded_canary_script_is_valid_python(self) -> None:
        source = _load_source(ENCODED_CANARY_SCRIPT)
        try:
            ast.parse(source)
        except SyntaxError as exc:
            raise AssertionError(f"Encoded canary script has syntax error: {exc}") from exc
