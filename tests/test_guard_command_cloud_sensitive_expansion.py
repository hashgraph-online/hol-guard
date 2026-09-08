"""Regression coverage for release 3.2 cloud secret and credential expansion."""

from __future__ import annotations

from pathlib import Path

from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases


def test_cloud_secret_and_credential_operations_are_reviewed(tmp_path: Path) -> None:
    assert_reviewed_command_cases(
        (
            (
                "aws secretsmanager get-secret-value --secret-id prod/api",
                "AWS secret or credential command",
                "command.cloud.aws.secret-or-credential",
            ),
            (
                "aws ssm get-parameter --name /prod/api --with-decryption",
                "AWS secret or credential command",
                "command.cloud.aws.secret-or-credential",
            ),
            (
                "aws iam create-access-key --user-name deploy",
                "AWS secret or credential command",
                "command.cloud.aws.secret-or-credential",
            ),
            (
                "gcloud secrets versions access latest --secret=prod-api",
                "Google Cloud secret or credential command",
                "command.cloud.gcp.secret-or-credential",
            ),
            (
                "gcloud auth print-access-token",
                "Google Cloud secret or credential command",
                "command.cloud.gcp.secret-or-credential",
            ),
            (
                "az keyvault secret show --vault-name prod --name api",
                "Azure secret or credential command",
                "command.cloud.azure.secret-or-credential",
            ),
            (
                "az account get-access-token",
                "Azure secret or credential command",
                "command.cloud.azure.secret-or-credential",
            ),
        ),
        tmp_path,
    )


def test_cloud_sensitive_help_and_non_decrypt_ssm_read_stay_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(
        (
            "aws secretsmanager get-secret-value --help",
            "aws ssm get-parameter --name /public/config",
            "gcloud secrets versions access --help",
            "az keyvault secret show --help",
        ),
        tmp_path,
    )
