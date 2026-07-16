"""Structured rules and metadata for search and messaging commands."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .command_database_matchers import LeadingSubcommandMatcher
from .command_extension_matchers import executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    CommandSafeVariant,
    ExecutableMatcher,
)

_CURL_EXECUTABLES = executable_names("curl")
_RABBITMQ_OPTIONS_WITH_VALUES = frozenset({"-n", "--node", "-t", "--timeout", "--formatter", "--erlang-cookie"})
_NATS_OPTIONS_WITH_VALUES = frozenset(
    {
        "-s",
        "--server",
        "--user",
        "--password",
        "--creds",
        "--nkey",
        "--tlscert",
        "--tlskey",
        "--tlsca",
        "--socks-proxy",
        "--colors",
        "--timeout",
        "--context",
    }
)


def _portable_script_names(name: str) -> frozenset[str]:
    return executable_names(name) | {f"{name}.bat", f"{name}.sh"}


@dataclass(frozen=True, slots=True)
class CurlElasticsearchDeleteMatcher:
    """Match explicit curl DELETE requests to recognizable Elasticsearch targets."""

    executables: frozenset[str] = _CURL_EXECUTABLES
    service_ports: frozenset[int] = frozenset({9200})

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            executable = (segment.executable or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            if executable not in self.executables:
                continue
            method, targets = _curl_method_and_targets(segment.arguments)
            if method != "delete" or not any(self._matches_target(target) for target in targets):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched an explicit DELETE request to an Elasticsearch API target.",
                )
            )
        return tuple(evidence)

    def _matches_target(self, target: str) -> bool:
        lowered = target.lower()
        if lowered.startswith(("$elasticsearch_", "${elasticsearch_")):
            return "/" in lowered
        try:
            parsed = urlsplit(target)
            port = parsed.port
        except ValueError:
            return False
        hostname = parsed.hostname or ""
        recognizable_host = port in self.service_ports or "elasticsearch" in hostname.split(".")
        return parsed.scheme in {"http", "https"} and recognizable_host and parsed.path not in {"", "/"}


def _curl_method_and_targets(arguments: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    method: str | None = None
    targets: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        lowered = argument.lower()
        if argument == "-x" or lowered == "--proxy":
            index += 2
            continue
        if (argument.startswith("-x") and len(argument) > 2) or lowered.startswith("--proxy="):
            index += 1
            continue
        if (argument == "-X" or lowered == "--request") and index + 1 < len(arguments):
            method = arguments[index + 1].lower()
            index += 2
            continue
        if lowered.startswith("--request="):
            method = lowered.split("=", 1)[1]
        elif argument.startswith("-X") and len(argument) > 2:
            method = argument[2:].lower()
        if argument.startswith(("http://", "https://", "$")):
            targets.append(argument.strip("'\""))
        index += 1
    return method, tuple(targets)


def _safe_flag_variant(
    executables: frozenset[str],
    *,
    variant_id: str,
    title: str,
    flag: str,
) -> CommandSafeVariant:
    return CommandSafeVariant(
        variant_id=variant_id,
        title=title,
        matcher=ExecutableMatcher(
            executables=executables,
            required_flags=frozenset({flag}),
            required_flags_in_all_arguments=True,
        ),
    )


_ELASTICSEARCH_DELETE = CurlElasticsearchDeleteMatcher()
_KAFKA_DELETE = AnyMatcher(
    matchers=(
        ExecutableMatcher(
            executables=_portable_script_names("kafka-topics"),
            required_flags=frozenset({"--delete"}),
            required_flags_in_all_arguments=True,
        ),
        ExecutableMatcher(
            executables=_portable_script_names("kafka-consumer-groups"),
            required_flags=frozenset({"--delete"}),
            required_flags_in_all_arguments=True,
        ),
        ExecutableMatcher(
            executables=_portable_script_names("kafka-consumer-groups"),
            required_flags=frozenset({"--delete-offsets"}),
            required_flags_in_all_arguments=True,
        ),
        ExecutableMatcher(
            executables=_portable_script_names("kafka-delete-records"),
            required_flags=frozenset({"--offset-json-file"}),
            required_flags_in_all_arguments=True,
        ),
    )
)
_RABBITMQ_EXECUTABLES = executable_names("rabbitmqctl") | {"rabbitmqctl.bat"}
_RABBITMQ_DELETE = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=_RABBITMQ_EXECUTABLES,
            subcommands=(command,),
            options_with_values=_RABBITMQ_OPTIONS_WITH_VALUES,
        )
        for command in ("delete_queue", "delete_user", "delete_vhost", "force_reset", "reset")
    )
)
_NATS_EXECUTABLES = executable_names("nats")
_NATS_DELETE = AnyMatcher(
    matchers=tuple(
        LeadingSubcommandMatcher(
            executables=_NATS_EXECUTABLES,
            subcommands=subcommands,
            options_with_values=_NATS_OPTIONS_WITH_VALUES,
        )
        for subcommands in (
            ("stream", "rm"),
            ("stream", "purge"),
            ("str", "rm"),
            ("str", "purge"),
            ("consumer", "rm"),
            ("con", "rm"),
            ("kv", "rm"),
            ("kv", "nuke"),
            ("object", "rm"),
            ("object", "nuke"),
            ("obj", "rm"),
            ("obj", "nuke"),
        )
    )
)


def _service_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    matcher: CommandMatcher,
    action_class: str,
    safer_alternative: str,
    safe_variants: tuple[CommandSafeVariant, ...] = (),
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="critical",
        risk_classes=("destructive_shell", "network_egress"),
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
        matcher=matcher,
        safe_variants=safe_variants,
    )


SEARCH_MESSAGING_COMMAND_RULES = (
    _service_rule(
        rule_id="command.search.elasticsearch.delete",
        title="Elasticsearch resource deletion",
        description="Identifies explicit DELETE requests to recognizable Elasticsearch APIs.",
        matcher=_ELASTICSEARCH_DELETE,
        action_class="Elasticsearch destructive command",
        safer_alternative="List the exact resource and capture its configuration before sending DELETE.",
    ),
    _service_rule(
        rule_id="command.messaging.kafka.delete",
        title="Kafka resource deletion",
        description="Identifies topic, consumer-group, offset, and record deletion operations.",
        matcher=_KAFKA_DELETE,
        action_class="Kafka destructive command",
        safer_alternative="Describe the exact topic or group and verify retention and recovery state first.",
        safe_variants=(
            safe_flag_variant(_KAFKA_DELETE, variant_id="help", title="Kafka command help", flag="--help"),
            safe_flag_variant(_KAFKA_DELETE, variant_id="version", title="Kafka version", flag="--version"),
        ),
    ),
    _service_rule(
        rule_id="command.messaging.rabbitmq.delete",
        title="RabbitMQ resource deletion",
        description="Identifies queue, user, virtual-host, and broker reset operations.",
        matcher=_RABBITMQ_DELETE,
        action_class="RabbitMQ destructive command",
        safer_alternative="List the target resource, bindings, permissions, and recovery policy first.",
        safe_variants=(
            _safe_flag_variant(
                _RABBITMQ_EXECUTABLES,
                variant_id="dry-run",
                title="RabbitMQ command preview",
                flag="--dry-run",
            ),
            _safe_flag_variant(_RABBITMQ_EXECUTABLES, variant_id="help", title="RabbitMQ command help", flag="--help"),
        ),
    ),
    _service_rule(
        rule_id="command.messaging.nats.delete",
        title="NATS resource deletion",
        description="Identifies stream, consumer, key-value, and object-store removal operations.",
        matcher=_NATS_DELETE,
        action_class="NATS destructive command",
        safer_alternative="Report the selected context and inspect the resource before removal or purge.",
        safe_variants=(
            _safe_flag_variant(_NATS_EXECUTABLES, variant_id="help", title="NATS command help", flag="--help"),
            _safe_flag_variant(_NATS_EXECUTABLES, variant_id="version", title="NATS version", flag="--version"),
        ),
    ),
)


SEARCH_MESSAGING_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.search.elasticsearch",
        name="Elasticsearch command protection",
        description="Reviews explicit DELETE requests to recognizable Elasticsearch API targets.",
        action_classes=("Elasticsearch destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List and export the target resource before sending DELETE.",),
        reference_urls=("https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-indices-delete",),
    ),
    CommandExtensionSpec(
        extension_id="command.messaging.kafka",
        name="Kafka command protection",
        description="Reviews Kafka topic, group, offset, and record deletion operations.",
        action_classes=("Kafka destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Describe the target and verify retention and recovery state first.",),
        reference_urls=("https://kafka.apache.org/documentation/",),
    ),
    CommandExtensionSpec(
        extension_id="command.messaging.rabbitmq",
        name="RabbitMQ command protection",
        description="Reviews RabbitMQ deletion and broker reset operations.",
        action_classes=("RabbitMQ destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("List bindings, permissions, and recovery state before deletion.",),
        reference_urls=("https://www.rabbitmq.com/docs/man/rabbitmqctl.8",),
    ),
    CommandExtensionSpec(
        extension_id="command.messaging.nats",
        name="NATS command protection",
        description="Reviews NATS stream, consumer, key-value, and object-store removal operations.",
        action_classes=("NATS destructive command",),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect the active context and selected resource before removal.",),
        reference_urls=("https://docs.nats.io/using-nats/nats-tools/nats_cli",),
    ),
)
