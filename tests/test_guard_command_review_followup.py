"""Regression coverage for the remaining release/3.2 command review findings."""

from __future__ import annotations

from pathlib import Path

from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

REVIEW_COMMENT_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "bunx cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "pnpm dlx cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "yarn dlx cdk destroy",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "npm exec -- sls remove",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "yarn dlx sls remove",
        "infrastructure destructive command",
        "command.infrastructure-as-code.runner-alias-teardown",
    ),
    (
        "pnpm exec railway shell",
        "Railway production command",
        "command.platform.railway.runner-alias-change",
    ),
    (
        "npm exec railway -- variables set API_TOKEN=value",
        "Railway production command",
        "command.platform.railway.runner-alias-change",
    ),
    (
        "bunx railway delete --yes",
        "Railway destructive command",
        "command.platform.railway.runner-alias-destructive",
    ),
    (
        "yarn dlx railway up",
        "Railway production command",
        "command.platform.railway.runner-alias-change",
    ),
    (
        "dotnet add src/MyApp/MyApp.csproj package Newtonsoft.Json",
        ".NET package mutation command",
        "command.package.dotnet.positional-project-package",
    ),
    (
        "psql '--command=TRUNCATE TABLE users'",
        "PostgreSQL destructive command",
        "command.database.postgresql.direct-drop",
    ),
    (
        "mysql '--execute=DROP TABLE users'",
        "MySQL destructive command",
        "command.database.mysql.direct-drop",
    ),
)


def test_remaining_review_launcher_forms_are_reviewed(tmp_path: Path) -> None:
    assert_reviewed_command_cases(REVIEW_COMMENT_CASES, tmp_path)


SAFE_REVIEW_COMMENT_CASES: tuple[str, ...] = (
    "bunx cdk destroy --help",
    "yarn dlx sls remove --help",
    "pnpm exec railway shell --help",
    "yarn dlx railway up --help",
    "psql '--command=SELECT 1'",
    "mysql '--execute=SELECT 1'",
)


def test_remaining_review_launcher_safe_forms_stay_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SAFE_REVIEW_COMMENT_CASES, tmp_path)
