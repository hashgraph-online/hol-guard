from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.secrets.secret_detection import scan_secret_text


def _parts(*values: str) -> str:
    return "".join(values)


def _github_token() -> str:
    return _parts(
        "gh",
        "p_",
        "Ab3d",
        "Ef5h",
        "Ij7l",
        "Mn9p",
        "Qr2t",
        "Uv4x",
        "Yz6B",
        "cd8F",
        "gh1J",
        "kl3N",
    )


def _google_api_key() -> str:
    return _parts(
        "AI",
        "za",
        "Ab3d",
        "Ef5h",
        "Ij7l",
        "Mn9p",
        "Qr2t",
        "Uv4x",
        "Yz6B",
        "cd8F",
        "gh1",
    )


def _pem_marker(kind: str) -> str:
    return _parts("-----", kind, " ", "OPENSSH", " ", "PRIVATE", " ", "KEY", "-----")


@pytest.mark.parametrize(
    ("source", "path"),
    [
        (
            "export type GuardSecretsOverview = Awaited<ReturnType<typeof loadSecretOverview>>;",
            "src/contracts.ts",
        ),
        (
            "const GUARD_SECRET_API_VERSION = 'guard-secrets-api.v1' as const;",
            "src/contracts.ts",
        ),
        (
            "const passwordInputId = 'email-auth-password';",
            "src/login.tsx",
        ),
        (
            "const TOKEN_URL = 'https://oauth.example.test/token';",
            "src/oauth.ts",
        ),
        (
            "secretName: points-staging-tls-secret",
            "deploy/ingress.yaml",
        ),
        (
            'implementation "androidx.credentials:credentials:1.5.0"',
            "android/app/build.gradle",
        ),
        (
            "handoff_token = $script:HANDOFF_TOKEN",
            "public/install.ps1",
        ),
    ],
)
def test_contextual_detector_ignores_metadata_and_code_expressions(source: str, path: str) -> None:
    assert scan_secret_text(source, path=path).findings == ()


@pytest.mark.parametrize(
    "source",
    [
        _parts("POSTGRES_", "PASSWORD", ': "<', "password", '>"'),
        _parts("API_", "KEY", ': "', "replace-with-", "api-key", '"'),
        _parts("SESSION_TOKEN_", "SECRET", ': "', "super-secret-", "session-key", '"'),
        _parts("AUTH_", "TOKEN", ': "', "invalid-", "token", '"'),
        _parts("PASS", "WORD", ': "', "Password", "123!", '"'),
    ],
)
def test_contextual_detector_ignores_explicit_example_placeholders(source: str) -> None:
    assert scan_secret_text(source, path="deploy/secret.example.yaml").findings == ()


def test_contextual_detector_keeps_random_secret_values_in_configuration() -> None:
    value = _parts("a9F3", "c7E1", "b5D8", "f2A6", "c4E9", "b7D1", "f5A8", "c2E6")
    result = scan_secret_text(f'SECRET_KEY: "{value}"', path="deploy/secrets.yaml")

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]


def test_contextual_detector_keeps_random_quoted_code_literal() -> None:
    value = _parts("v1_", "R4nd", "0mCr", "ed3n", "tial", "_8Zk", "9Qp2", "Lm7")
    result = scan_secret_text(f'const clientSecret = "{value}";', path="src/auth.ts")

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]


def test_contextual_detector_ignores_public_protocol_identifier() -> None:
    identifier = _parts("5098d5ba", "65ef838b", "bd6d3f29", "3327884b")
    result = scan_secret_text(
        f"const INDEXNOW_API_KEY = '{identifier}';",
        path="src/indexnow.ts",
    )

    assert result.findings == ()


def test_provider_fixture_is_suppressed_in_nearby_redaction_test_context() -> None:
    token = _github_token()
    result = scan_secret_text(
        "\n".join(
            (
                "describe('redaction', () => {",
                "  it('removes provider tokens', () => {",
                f"    expect(redact('token {token}')).not.toContain('{token}');",
                "  });",
                "});",
            )
        ),
        path="__tests__/redaction.test.ts",
    )

    assert result.findings == ()


def test_provider_fixture_without_test_context_remains_detectable() -> None:
    token = _github_token()
    result = scan_secret_text(f"GITHUB_TOKEN={token}", path="tests/accidental.env")

    assert [finding.rule_id for finding in result.findings] == ["github-token"]


def test_public_google_client_configuration_is_not_treated_as_server_secret() -> None:
    key = _google_api_key()

    assert scan_secret_text(f'{{"current_key": "{key}"}}', path="android/google-services.json").findings == ()
    assert [
        finding.rule_id for finding in scan_secret_text(f"GOOGLE_API_KEY={key}", path=".env.production").findings
    ] == ["google-api-key"]


def test_private_key_fixture_is_suppressed_but_production_header_is_detected() -> None:
    begin = _pem_marker("BEGIN")
    end = _pem_marker("END")
    fixture = _parts(
        "fixtureContents: {\n",
        "  key: '",
        begin,
        "\\nfixture-not-real-key-content\\n",
        end,
        "',\n}",
    )
    assert scan_secret_text(fixture, path="src/benchmark-scenarios.ts").findings == ()

    body = _parts("AbCd", "Ef12", "3456", "7890", "AbCd", "Ef12", "3456", "7890")
    result = scan_secret_text(
        _parts(begin, "\n", body, "\n", end),
        path="config/id_ed25519",
    )
    assert [finding.rule_id for finding in result.findings] == ["pem-private-key"]
