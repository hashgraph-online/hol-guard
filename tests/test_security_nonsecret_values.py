"""Non-secret token expressions must not hide adjacent or embedded credentials."""

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.checks.security import (
    SecretPattern,
    _field_name_map_spans,
    _first_hardcoded_secret_line,
    _should_skip_secret_match,
)

FIELD_MAP = """const SUFFIX_BY_FIELD: Record<Field, string> = {
  publicationUrl: "PUBLICATION_URL",
  sessionToken: "SESSION_TOKEN",
  userId: "USER_ID",
};"""


@pytest.mark.parametrize("path", ["scripts/start.sh", "src/config.py", "src/provider.ts"])
@pytest.mark.parametrize(
    "content",
    [
        'API_KEY="${GEMINI_API_KEY:-}"',
        'api_key = "${GEMINI_API_KEY}"',
        'token = "{{secrets.GEMINI_API_KEY}}"',
        'API_KEY="${GEMINI_API_KEY:-$BACKUP_KEY}"',
    ],
)
def test_interpolated_secret_values_are_not_hardcoded(path, content):
    """Variable expansions are references, including in production scripts."""
    assert _first_hardcoded_secret_line(Path(path), content) is None


@pytest.mark.parametrize(
    "content",
    [
        'password="${PASSWORD:-actual-pass-937}"',
        'password="${PASSWORD}actual-pass-937"',
        'API_KEY="${API_KEY:-actual-secret-937}"',
    ],
)
def test_interpolations_with_literal_payloads_still_fire(content):
    """A non-empty default or suffix is still embedded credential material."""
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) == 1


def test_interpolated_assignment_does_not_hide_adjacent_secret():
    content = 'API_KEY="${GEMINI_API_KEY:-}"\npassword="actual-pass-937"'
    assert _first_hardcoded_secret_line(Path("scripts/start.sh"), content) == 2


@pytest.mark.parametrize("path", ["README.md", "examples/docker.md", "scripts/start.sh"])
@pytest.mark.parametrize("encoding", ["hex", "base64"])
def test_generated_token_expression_is_not_a_literal_secret(path, encoding):
    """Both supported encodings generate values rather than embed literal credentials."""
    content = f'MCP_HTTP_TOKEN="$(openssl rand -{encoding} 32)"'
    assert _first_hardcoded_secret_line(Path(path), content) is None


@pytest.mark.parametrize(
    "content",
    [
        "MCP_HTTP_TOKEN='$(openssl rand -hex 32)'",
        'MCP_HTTP_TOKEN="$(openssl rand -hex 32)-literal-suffix"',
        'MCP_HTTP_TOKEN="$(openssl rand -hex 32)"literal-suffix',
        'MCP_HTTP_TOKEN="$(openssl rand -hex 32; echo literal-value)"',
        'MCP_HTTP_TOKEN="$(printf literal-value)"',
        'MCP_HTTP_TOKEN="$(openssl rand -hex 32)',
        'MCP_HTTP_TOKEN="$(openssl rand -hex 32)"\npassword="actual-pass-937"',
    ],
)
def test_other_shell_values_and_adjacent_secrets_still_fire(content):
    """Reject malformed or literal substitutions without hiding adjacent credentials."""
    assert _first_hardcoded_secret_line(Path("README.md"), content) is not None


def test_generated_expression_in_non_shell_source_remains_a_literal():
    """Do not interpret shell syntax as executable generation inside Python strings."""
    content = 'token="$(openssl rand -hex 32)"'
    assert _first_hardcoded_secret_line(Path("src/config.py"), content) == 1


@pytest.mark.parametrize("path", ["src/config.ts", "src/config.tsx"])
def test_typed_field_name_map_is_not_a_credential_assignment(path):
    """Recognize complete field-name dictionaries in both TS and TSX source files."""
    assert _first_hardcoded_secret_line(Path(path), FIELD_MAP) is None


@pytest.mark.parametrize("path", ["src/config.js", "README.md"])
def test_field_name_maps_outside_typescript_still_fire(path):
    """Keep the typed-map exemption confined to TypeScript file extensions."""
    assert _first_hardcoded_secret_line(Path(path), FIELD_MAP) is not None


def test_reverse_field_name_map_is_not_a_credential_assignment():
    """Accept the inverse mapping from uppercase suffixes to camel-case field names."""
    content = """const FIELD_BY_SUFFIX: Record<string, Field> = {
      PUBLICATION_URL: "publicationUrl",
      SESSION_TOKEN: "sessionToken",
      USER_ID: "userId",
    };"""
    assert _first_hardcoded_secret_line(Path("src/config.ts"), content) is None


@pytest.mark.parametrize(
    "content",
    [
        'const credentials = { sessionToken: "SESSION_TOKEN" };',
        'const credentials: Record<string, string> = { sessionToken: "SESSION_TOKEN" };',
        FIELD_MAP.replace('"SESSION_TOKEN"', '"actual-pass-937"'),
        FIELD_MAP + '\nconst sessionToken = "actual-pass-937";',
        FIELD_MAP.replace('"USER_ID"', '"literal-value"'),
    ],
)
def test_non_mapping_values_and_adjacent_credentials_still_fire(content):
    """Require every map entry to qualify and retain detection outside valid maps."""
    assert _first_hardcoded_secret_line(Path("src/config.ts"), content) is not None


def test_provider_secret_is_not_exempted_by_a_generated_token_line():
    """A generated generic token must not exempt a provider token on the same line."""
    # Synthetic regression payload, not a credential.
    provider_value = "ghp_" + "Q7vN2mL9rT5xB8cD1fG6hJ3kP4sW0zY2uA9b"
    content = f'MCP_HTTP_TOKEN="$(openssl rand -hex 32)" # {provider_value}'
    assert _first_hardcoded_secret_line(Path("README.md"), content) == 1


@pytest.mark.parametrize(
    ("path", "content", "pattern"),
    [
        ("src/config.ts", FIELD_MAP + '\nconst password = "actual-pass-937";', r'Token: "(.+)"'),
        ("README.md", 'TOKEN="$(openssl rand -hex 32)"\npassword="actual-pass-937"', r'TOKEN="(.+)"'),
    ],
)
def test_future_broader_detector_cannot_cross_an_exempted_region(path, content, pattern):
    """Require full containment even if a future generic detector spans multiple lines."""
    detector = SecretPattern(re.compile(pattern, re.DOTALL), kind="generic", value_group=1)
    match = detector.pattern.search(content)
    assert match is not None
    assert not _should_skip_secret_match(
        Path(path), content, detector, match, field_name_spans=_field_name_map_spans(Path(path), content)
    )
