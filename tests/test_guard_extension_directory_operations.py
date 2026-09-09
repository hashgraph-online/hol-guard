"""Public directory operations expose matcher commands and catalog default floors."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extension_matchers import executable_matcher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher
from codex_plugin_scanner.guard.runtime.command_rules import AnyMatcher
from codex_plugin_scanner.guard.runtime.extension_directory_operations import (
    command_signatures_for_matcher,
    public_operations,
)


def test_command_signatures_use_canonical_executable_and_required_flags() -> None:
    matcher = AnyMatcher(
        matchers=(
            executable_matcher("aws", "s3", "rm"),
            executable_matcher("aws", "s3", "sync", required_flags=frozenset({"--delete"})),
            executable_matcher("aws", "s3api", "delete-object"),
        )
    )
    assert command_signatures_for_matcher(matcher) == (
        "aws s3 rm",
        "aws s3 sync --delete",
        "aws s3api delete-object",
    )


def test_path_set_signatures_expand_each_path_once() -> None:
    matcher = ExecutablePathSetMatcher(
        executables=frozenset({"kubectl", "kubectl.exe"}),
        paths=frozenset({("delete", "pod"), ("delete", "namespace")}),
    )
    assert command_signatures_for_matcher(matcher) == (
        "kubectl delete namespace",
        "kubectl delete pod",
    )


def test_aws_s3_operations_list_commands_and_default_floors() -> None:
    extension = next(
        item for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if item.extension_id == "command.storage.aws-s3"
    )
    operations = {row["id"]: row for row in public_operations(extension)}
    assert set(operations) == {
        "command.storage.aws-s3.deletion",
        "command.storage.aws-s3.cp",
        "command.storage.aws-s3.ls",
        "command.storage.aws-s3.mb",
        "command.storage.aws-s3.mv",
        "command.storage.aws-s3.presign",
        "command.storage.aws-s3.sync",
        "command.storage.aws-s3.website",
    }
    deletion = operations["command.storage.aws-s3.deletion"]
    assert deletion["severity"] == "critical"
    assert deletion["defaultMode"] == "review"
    assert deletion["defaultAction"] == "review"
    assert deletion["permissionId"] == "command.storage.aws-s3.permission.deletion"
    commands = deletion["commands"]
    assert isinstance(commands, list)
    for command in (
        "aws s3 rm",
        "aws s3 rb",
        "aws s3 sync --delete",
        "aws s3api delete-object",
        "aws s3api delete-objects",
        "aws s3api delete-bucket",
    ):
        assert command in commands
    assert deletion["safeVariants"] == ["--help", "--dryrun"]
    listing = operations["command.storage.aws-s3.ls"]
    assert listing["defaultMode"] == "disabled"
    assert listing["defaultAction"] == "allow"
    assert listing["commands"] == ["aws s3 ls"]
    assert operations["command.storage.aws-s3.sync"]["commands"] == ["aws s3 sync"]


def test_required_critical_rules_publish_a_block_floor() -> None:
    extension = next(
        item for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions if item.extension_id == "command.filesystem"
    )
    operations = public_operations(extension)
    assert operations
    assert all(row["defaultAction"] == "block" for row in operations if row["severity"] == "critical")
    assert all(row["defaultAction"] in {"block", "review"} for row in operations)
