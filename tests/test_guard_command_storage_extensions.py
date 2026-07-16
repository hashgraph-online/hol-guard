"""Structured object-storage command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        (
            "aws s3 rm s3://archive/private.json",
            "AWS storage destructive command",
            "command.storage.aws-s3.deletion",
        ),
        (
            "aws s3 --region us-east-1 sync ./out s3://archive --delete",
            "AWS storage destructive command",
            "command.storage.aws-s3.deletion",
        ),
        (
            "aws.exe s3api delete-objects --bucket archive --delete file://objects.json",
            "AWS storage destructive command",
            "command.storage.aws-s3.deletion",
        ),
        (
            "aws --no-cli-pager s3 rm s3://archive/private.json",
            "AWS storage destructive command",
            "command.storage.aws-s3.deletion",
        ),
        (
            "gcloud storage --project app-prod rm --recursive gs://archive/old",
            "Google storage destructive command",
            "command.storage.google-cloud.deletion",
        ),
        (
            "gsutil.cmd -m rsync -d ./out gs://archive",
            "Google storage destructive command",
            "command.storage.google-cloud.deletion",
        ),
        (
            "gcloud storage rsync ./out gs://archive --delete-unmatched-destination-objects -n",
            "Google storage destructive command",
            "command.storage.google-cloud.deletion",
        ),
        (
            "gcloud --quiet storage rm gs://archive/private.json",
            "Google storage destructive command",
            "command.storage.google-cloud.deletion",
        ),
        (
            "az.cmd storage blob delete-batch --subscription app-prod --source archive",
            "Azure storage destructive command",
            "command.storage.azure-blob.deletion",
        ),
        (
            "az --debug storage blob delete --container-name archive --name private.json",
            "Azure storage destructive command",
            "command.storage.azure-blob.deletion",
        ),
        (
            "mc.exe mirror --remove ./out prod/archive",
            "MinIO storage destructive command",
            "command.storage.minio.deletion",
        ),
        (
            "mc --config-dir /tmp/mc rm prod/archive/private.json",
            "MinIO storage destructive command",
            "command.storage.minio.deletion",
        ),
        (
            "mc --json mirror --remove ./out prod/archive",
            "MinIO storage destructive command",
            "command.storage.minio.deletion",
        ),
    ],
)
def test_storage_rules_feed_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "aws s3 rm s3://archive/private.json --dryrun",
        "aws s3 sync ./out s3://archive --delete --dryrun",
        "gcloud storage rsync ./out gs://archive --delete-unmatched-destination-objects --dry-run",
        "gsutil -m rsync -d -n ./out gs://archive",
        "az storage blob delete-batch --source archive --dryrun",
        "mc rm --help",
        "aws s3 ls s3://archive",
        "gcloud storage ls gs://archive",
        "az storage blob list --container-name archive",
        "mc ls prod/archive",
        "mc --config-dir /tmp/mc ls prod/archive",
        "mc --help rm prod/archive",
        "grep 's3 rm|storage rm|blob delete|mc rm' scripts/guard-test",
        "printf '%s\\n' 'aws s3 rm s3://archive/private.json'",
    ],
)
def test_storage_preview_and_read_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_storage_safe_segment_does_not_hide_later_deletion(tmp_path: Path) -> None:
    payload = inspect_command(
        "aws s3 rm s3://archive/a --dryrun && mc rm prod/archive/a",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.storage.minio.deletion"]


def test_storage_extensions_publish_official_references() -> None:
    extension_ids = (
        "command.storage.aws-s3",
        "command.storage.google-cloud",
        "command.storage.azure-blob",
        "command.storage.minio",
    )
    for extension_id in extension_ids:
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
