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
_CURL_SHORT_OPTIONS_WITH_VALUES = frozenset(
    {
        "A",
        "b",
        "c",
        "C",
        "d",
        "D",
        "e",
        "E",
        "F",
        "H",
        "K",
        "m",
        "o",
        "P",
        "Q",
        "r",
        "t",
        "T",
        "u",
        "U",
        "w",
        "x",
        "X",
        "y",
        "Y",
        "z",
    }
)
_CURL_LONG_OPTIONS_WITH_VALUES = frozenset(
    {
        "--abstract-unix-socket",
        "--alt-svc",
        "--aws-sigv4",
        "--cacert",
        "--capath",
        "--cert",
        "--cert-type",
        "--ciphers",
        "--config",
        "--connect-timeout",
        "--connect-to",
        "--cookie",
        "--cookie-jar",
        "--create-file-mode",
        "--crlfile",
        "--curves",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--delegation",
        "--dns-interface",
        "--dns-ipv4-addr",
        "--dns-ipv6-addr",
        "--dns-servers",
        "--doh-url",
        "--dump-header",
        "--ech",
        "--egd-file",
        "--engine",
        "--etag-compare",
        "--etag-save",
        "--expect100-timeout",
        "--form",
        "--form-string",
        "--ftp-account",
        "--ftp-alternative-to-user",
        "--ftp-method",
        "--ftp-port",
        "--ftp-ssl-ccc-mode",
        "--happy-eyeballs-timeout-ms",
        "--haproxy-clientip",
        "--header",
        "--hostpubmd5",
        "--hostpubsha256",
        "--hsts",
        "--interface",
        "--ip-tos",
        "--ipfs-gateway",
        "--json",
        "--keepalive-time",
        "--keepalive-cnt",
        "--key",
        "--key-type",
        "--krb",
        "--libcurl",
        "--limit-rate",
        "--local-port",
        "--login-options",
        "--mail-auth",
        "--mail-from",
        "--mail-rcpt",
        "--max-filesize",
        "--max-redirs",
        "--max-time",
        "--netrc-file",
        "--noproxy",
        "--oauth2-bearer",
        "--output",
        "--output-dir",
        "--parallel-max",
        "--parallel-max-host",
        "--pass",
        "--pinnedpubkey",
        "--preproxy",
        "--proto",
        "--proto-default",
        "--proto-redir",
        "--proxy",
        "--proxy-cacert",
        "--proxy-capath",
        "--proxy-cert",
        "--proxy-cert-type",
        "--proxy-ciphers",
        "--proxy-crlfile",
        "--proxy-header",
        "--proxy-key",
        "--proxy-key-type",
        "--proxy-pass",
        "--proxy-pinnedpubkey",
        "--proxy-service-name",
        "--proxy-tls13-ciphers",
        "--proxy-tlsauthtype",
        "--proxy-tlspassword",
        "--proxy-tlsuser",
        "--proxy-user",
        "--proxy1.0",
        "--pubkey",
        "--quote",
        "--random-file",
        "--range",
        "--rate",
        "--referer",
        "--request-target",
        "--resolve",
        "--retry",
        "--retry-delay",
        "--retry-max-time",
        "--sasl-authzid",
        "--service-name",
        "--speed-limit",
        "--speed-time",
        "--socks4",
        "--socks4a",
        "--socks5",
        "--socks5-hostname",
        "--socks5-gssapi-service",
        "--stderr",
        "--telnet-option",
        "--tftp-blksize",
        "--tls-max",
        "--tls-earlydata",
        "--tls13-ciphers",
        "--tlsauthtype",
        "--tlspassword",
        "--tlsuser",
        "--time-cond",
        "--trace",
        "--trace-ascii",
        "--trace-config",
        "--unix-socket",
        "--upload-file",
        "--upload-flags",
        "--user",
        "--user-agent",
        "--url-query",
        "--variable",
        "--vlan-priority",
        "--write-out",
    }
)
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
            operations = _curl_operations(segment.arguments)
            if not any(
                method == "delete" and any(self._matches_target(target) for target in targets)
                for method, targets in operations
            ):
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
        normalized = target.strip("'\"")
        lowered = normalized.lower()
        if lowered.startswith(("$elasticsearch_", "${elasticsearch_")):
            return "/" in lowered
        try:
            explicit_scheme = "://" in normalized
            parsed = urlsplit(normalized if explicit_scheme else f"//{normalized}")
            port = parsed.port
        except ValueError:
            return False
        hostname = parsed.hostname or ""
        recognizable_host = port in self.service_ports or "elasticsearch" in hostname.split(".")
        supported_scheme = parsed.scheme in {"http", "https"} if explicit_scheme else not parsed.scheme
        return supported_scheme and recognizable_host and parsed.path not in {"", "/"}


def _curl_operations(arguments: tuple[str, ...]) -> tuple[tuple[str | None, tuple[str, ...]], ...]:
    operations: list[tuple[str | None, tuple[str, ...]]] = []
    method: str | None = None
    targets: list[str] = []
    index = 0
    parse_options = True
    while index < len(arguments):
        argument = arguments[index]
        lowered = argument.lower()
        if parse_options and argument == "--":
            parse_options = False
            index += 1
            continue
        if not parse_options:
            targets.append(argument.strip("'\""))
            index += 1
            continue
        if lowered == "--next":
            operations.append((method, tuple(targets)))
            method = None
            targets = []
            index += 1
            continue
        if lowered == "--request" and index + 1 < len(arguments):
            method = arguments[index + 1].lower()
            index += 2
            continue
        if lowered.startswith("--request="):
            method = argument.split("=", 1)[1].lower()
            index += 1
            continue
        if lowered == "--url" and index + 1 < len(arguments):
            targets.append(arguments[index + 1].strip("'\""))
            index += 2
            continue
        if lowered.startswith("--url="):
            targets.append(argument.split("=", 1)[1].strip("'\""))
            index += 1
            continue
        long_option = lowered.split("=", 1)[0]
        if long_option in _CURL_LONG_OPTIONS_WITH_VALUES:
            index += 1 if "=" in argument else 2
            continue
        if argument.startswith("-") and not argument.startswith("--") and len(argument) > 1:
            consumed_next = False
            for offset, short_option in enumerate(argument[1:], start=1):
                if short_option not in _CURL_SHORT_OPTIONS_WITH_VALUES:
                    continue
                attached_value = argument[offset + 1 :]
                if not attached_value and index + 1 < len(arguments):
                    attached_value = arguments[index + 1]
                    consumed_next = True
                if short_option == "X":
                    method = attached_value.lower()
                break
            index += 2 if consumed_next else 1
            continue
        if not argument.startswith("-"):
            targets.append(argument.strip("'\""))
        index += 1
    operations.append((method, tuple(targets)))
    return tuple(operations)


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
