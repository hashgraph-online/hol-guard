from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.secrets.secret_detection import detector_version, scan_secret_text


@pytest.mark.parametrize(
    ("source", "path"),
    [
        (
            "\n".join(
                (
                    'const authToken = request.headers.get("authorization");',
                    "const apiKey = process.env.OPENAI_API_KEY;",
                    "const clientSecret = config.auth.clientSecret;",
                    "const password = crypto.randomUUID();",
                    "const webhookToken = values.webhookToken;",
                    "const bearerToken = tokenFromRequest;",
                )
            ),
            "src/auth.ts",
        ),
        (
            "\n".join(
                (
                    "api_key = os.getenv('OPENAI_API_KEY')",
                    "password = settings.database_password",
                    "auth_token = context.secrets.auth_token",
                )
            ),
            "src/auth.py",
        ),
        (
            "\n".join(
                (
                    "apiKey: z.string().min(20)",
                    "clientSecret: schema.clientSecret",
                    "accessToken: request?.auth?.accessToken",
                )
            ),
            "src/schema.ts",
        ),
    ],
)
def test_contextual_assignments_ignore_indirect_code_references(source: str, path: str) -> None:
    result = scan_secret_text(source, path=path)

    assert result.findings == ()


def test_contextual_assignments_ignore_quoted_environment_references() -> None:
    result = scan_secret_text(
        'const apiKey = "process.env.OPENAI_API_KEY";',
        path="src/auth.ts",
    )

    assert result.findings == ()


def test_contextual_assignments_keep_quoted_literal_credentials_in_code() -> None:
    candidate = "v1_" + "R4nd0mCred3ntial_8Zk9Qp2Lm7"
    result = scan_secret_text(
        f'const apiKey = "{candidate}";',
        path="src/auth.ts",
    )

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]
    assert result.findings[0].candidate == candidate


def test_contextual_assignments_keep_unquoted_dotenv_credentials() -> None:
    candidate = "v1_" + "R4nd0mCred3ntial_8Zk9Qp2Lm7"
    result = scan_secret_text(
        f"AUTH_TOKEN={candidate}",
        path=".env",
    )

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]
    assert result.findings[0].candidate == candidate


def test_detector_version_tracks_generic_assignment_precision_policy() -> None:
    assert detector_version().startswith("guard-secrets-v1:")
    assert len(detector_version().split(":", maxsplit=1)[1]) == 16
