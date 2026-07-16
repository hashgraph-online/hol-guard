"""Structured search and messaging command extension tests."""

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
            "curl -X DELETE http://localhost:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl.exe --request=DELETE '$ELASTICSEARCH_URL/_data_stream/events'",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl -X DELETE -x http://proxy.example http://localhost:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl -X DELETE --url localhost:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl -X DELETE --url=http://localhost:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl -X DELETE --url=localhost:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "curl -X DELETE elasticsearch:9200/customer-index",
            "Elasticsearch destructive command",
            "command.search.elasticsearch.delete",
        ),
        (
            "kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic events",
            "Kafka destructive command",
            "command.messaging.kafka.delete",
        ),
        (
            "kafka-consumer-groups.bat --bootstrap-server localhost:9092 "
            "--delete-offsets --group workers --topic events",
            "Kafka destructive command",
            "command.messaging.kafka.delete",
        ),
        (
            "kafka-delete-records --bootstrap-server localhost:9092 --offset-json-file offsets.json",
            "Kafka destructive command",
            "command.messaging.kafka.delete",
        ),
        (
            "rabbitmqctl -n rabbit@host delete_vhost production",
            "RabbitMQ destructive command",
            "command.messaging.rabbitmq.delete",
        ),
        (
            "rabbitmqctl.bat force_reset",
            "RabbitMQ destructive command",
            "command.messaging.rabbitmq.delete",
        ),
        (
            "nats --server nats://localhost:4222 stream rm EVENTS",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
        (
            "nats.exe --context production kv rm sessions",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
        (
            "nats str purge EVENTS --force",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
        (
            "nats con rm ORDERS PROCESSOR",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
        (
            "nats obj nuke artifacts --force",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
        (
            "nats kv nuke sessions --force",
            "NATS destructive command",
            "command.messaging.nats.delete",
        ),
    ],
)
def test_search_messaging_rules_feed_runtime_hooks(
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
        "curl -X DELETE https://api.example.com/users/1",
        "curl -X DELETE https://api.example.com/_snapshot/old",
        "curl -X DELETE --url api.example.com/users/1",
        "curl -X DELETE --url=https://api.example.com/users/1",
        "curl -x http://localhost:9200/customer-index https://api.example.com/users/1",
        "curl http://localhost:9200/customer-index",
        "curl --url localhost:9200/customer-index",
        "curl -X GET http://localhost:9200/customer-index",
        "kafka-topics.sh --bootstrap-server localhost:9092 --list",
        "kafka-topics.sh --delete --help",
        "rabbitmqctl list_vhosts",
        "rabbitmqctl delete_vhost production --dry-run",
        "rabbitmqctl delete_user operator --help",
        "nats stream ls",
        "nats stream rm EVENTS --help",
        "grep 'curl -X DELETE|kafka-topics --delete|rabbitmqctl delete_vhost|nats stream rm' docs",
    ],
)
def test_search_messaging_observer_and_preview_commands_remain_safe(command: str, tmp_path: Path) -> None:
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


def test_search_messaging_extensions_publish_official_references() -> None:
    for extension_id in (
        "command.search.elasticsearch",
        "command.messaging.kafka",
        "command.messaging.rabbitmq",
        "command.messaging.nats",
    ):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
