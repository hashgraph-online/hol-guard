"""Public directory operations use generated catalog examples and floors."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_directory_operations import public_operations


def _operations(extension_id: str) -> dict[str, dict[str, object]]:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)
    assert extension is not None
    return {str(row["id"]): row for row in public_operations(extension)}


def test_public_operations_only_use_unambiguous_permission_examples() -> None:
    for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        operations = _operations(extension.extension_id)
        assert set(operations) == {rule.rule_id for rule in extension.rules}
        for rule in extension.rules:
            permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission_for_rule_id(rule.rule_id)
            assert permission is not None
            expected = (
                [permission.example_command]
                if permission.example_command and permission.rule_ids == (rule.rule_id,)
                else []
            )
            assert operations[rule.rule_id]["commands"] == expected


def test_shared_mutation_permissions_do_not_publish_opposite_operation_examples() -> None:
    for extension_id, rule_ids in (
        ("command.routed", ("command.routed.adapters-install", "command.routed.adapters-uninstall")),
        (
            "command.xencode",
            (
                "command.xencode.worktree-add",
                "command.xencode.worktree-remove",
                "command.xencode.plugin-install",
                "command.xencode.plugin-remove",
            ),
        ),
    ):
        operations = _operations(extension_id)
        for rule_id in rule_ids:
            assert operations[rule_id]["example"] is None
            assert operations[rule_id]["commands"] == []
            assert operations[rule_id]["permissionId"] is not None
            assert operations[rule_id]["defaultAction"] == "review"

    assert _operations("command.routed")["command.routed.update"]["example"] == "routed update"


def test_aws_s3_operations_keep_generated_examples_defaults_and_permissions() -> None:
    operations = _operations("command.storage.aws-s3")
    deletion = operations["command.storage.aws-s3.deletion"]
    assert deletion["commands"] == ["aws s3 rm"]
    assert deletion["severity"] == "critical"
    assert deletion["defaultMode"] == "review"
    assert deletion["defaultAction"] == "review"
    assert deletion["permissionId"] == "command.storage.aws-s3.permission.deletion"
    assert deletion["safeVariants"] == [
        "Amazon S3 deletion help",
        "Amazon S3 deletion dry run",
        "Amazon S3 deletion request skeleton",
    ]
    assert operations["command.storage.aws-s3.ls"]["commands"] == ["aws s3 ls"]
    assert operations["command.storage.aws-s3.ls"]["defaultAction"] == "allow"
    assert operations["command.storage.aws-s3.sync"]["commands"] == ["aws s3 sync"]
    assert operations["command.storage.aws-s3.object-write"]["commands"] == ["aws s3api put-object"]
    assert operations["command.storage.aws-s3.download"]["commands"] == ["aws s3api get-object"]


def test_conjunctive_and_pipeline_examples_are_preserved_as_generated_metadata() -> None:
    assert _operations("command.probe")["command.probe.request-output"]["commands"] == [
        "probe request run api.yml items/0 --output response.json"
    ]
    assert _operations("command.encoded-execution")["command.encoded-execution.decode-and-execute"]["commands"] == [
        "echo <base64> | base64 --decode | sh"
    ]
    assert _operations("command.container-runtime")["command.container-runtime.compose-destructive-cleanup"][
        "commands"
    ] == ["docker compose down --volumes"]
    assert _operations("command.search.elasticsearch")["command.search.elasticsearch.delete"]["commands"] == [
        "curl -X DELETE 'https://localhost:9200/logs-old'"
    ]


def test_required_critical_rules_publish_a_block_floor() -> None:
    operations = _operations("command.filesystem").values()
    assert operations
    assert all(row["defaultAction"] == "block" for row in operations if row["severity"] == "critical")
    assert all(row["defaultAction"] in {"block", "review"} for row in operations)
