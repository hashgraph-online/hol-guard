"""Versioned, backend-neutral contracts for Guard network mediation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from typing import Final, cast

NETWORK_POLICY_SCHEMA_VERSION: Final = "guard.network-policy.v1"
NETWORK_BROKER_SCHEMA_VERSION: Final = "guard.network-broker.v1"
NETWORK_BACKEND_SCHEMA_VERSION: Final = "guard.network-backend.v1"
NETWORK_EVIDENCE_SCHEMA_VERSION: Final = "guard.network-evidence.v1"
NETWORK_PRIVACY_SCHEMA_VERSION: Final = "guard.network-privacy.v1"

_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_STABLE_ID: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_LABEL: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class NetworkAction(str, Enum):
    DENY = "deny"
    APPROVE = "approve"
    ALLOW = "allow"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    UNKNOWN = "unknown"


class DestinationKind(str, Enum):
    HOST = "host"
    IP = "ip"
    CIDR = "cidr"
    PRIVATE_CLASS = "private-class"


class PrivateNetworkClass(str, Enum):
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"
    PRIVATE = "private"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"


class ProcessScopeKind(str, Enum):
    INSTALLATION = "installation"
    SESSION = "session"


class EnforcementGrade(str, Enum):
    UNAVAILABLE = "unavailable"
    OBSERVE = "observe"
    DENY_ALL = "deny-all"
    PROXY_ONLY = "proxy-only"
    DESTINATION_ENFORCED = "destination-enforced"


class BackendCapability(str, Enum):
    OBSERVE = "observe"
    DENY_ALL = "deny-all"
    TCP_DESTINATION = "tcp-destination"
    UDP_DESTINATION = "udp-destination"
    DNS_CORRELATION = "dns-correlation"
    PROXY_ONLY = "proxy-only"
    PROCESS_TREE = "process-tree"
    ATOMIC_POLICY = "atomic-policy"
    RECEIPTS = "receipts"


_GRADE_REQUIREMENTS: Final[dict[EnforcementGrade, frozenset[BackendCapability]]] = {
    EnforcementGrade.UNAVAILABLE: frozenset(),
    EnforcementGrade.OBSERVE: frozenset({BackendCapability.OBSERVE}),
    EnforcementGrade.DENY_ALL: frozenset({BackendCapability.DENY_ALL}),
    EnforcementGrade.PROXY_ONLY: frozenset({BackendCapability.PROXY_ONLY, BackendCapability.PROCESS_TREE}),
    EnforcementGrade.DESTINATION_ENFORCED: frozenset(
        {
            BackendCapability.TCP_DESTINATION,
            BackendCapability.UDP_DESTINATION,
            BackendCapability.DNS_CORRELATION,
            BackendCapability.PROCESS_TREE,
            BackendCapability.RECEIPTS,
        }
    ),
}


def grade_required_capabilities(grade: EnforcementGrade) -> frozenset[BackendCapability]:
    if not isinstance(grade, EnforcementGrade):
        raise ValueError("grade must be exact")
    return _GRADE_REQUIREMENTS[grade]


class PolicyOwner(str, Enum):
    BUILTIN = "builtin"
    LOCAL = "local"
    WORKSPACE = "workspace"
    ORGANIZATION = "organization"
    EMERGENCY = "emergency"


class FailureMode(str, Enum):
    DENY = "deny"
    OFFLINE = "offline"
    REQUIRE_APPROVAL = "require-approval"


@dataclass(frozen=True, slots=True)
class Destination:
    kind: DestinationKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), DestinationKind):
            raise ValueError("destination kind must be exact")
        canonical = canonical_destination(self.kind, self.value)
        object.__setattr__(self, "value", canonical)


@dataclass(frozen=True, slots=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if type(self.start) is not int or type(self.end) is not int:
            raise ValueError("ports must be integers")
        if not 1 <= self.start <= self.end <= 65535:
            raise ValueError("ports must be within 1..65535")


@dataclass(frozen=True, slots=True)
class ProcessTreeIdentity:
    installation_id: str
    session_id: str
    root_pid: int
    root_start_time_ns: int
    executable_digest: str

    def __post_init__(self) -> None:
        require_id(self.installation_id, "installation_id")
        require_id(self.session_id, "session_id")
        if type(self.root_pid) is not int or self.root_pid <= 0:
            raise ValueError("root_pid must be a positive integer")
        if type(self.root_start_time_ns) is not int or self.root_start_time_ns <= 0:
            raise ValueError("root_start_time_ns must be a positive integer")
        require_digest(self.executable_digest, "executable_digest")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ProcessScope:
    kind: ProcessScopeKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), ProcessScopeKind):
            raise ValueError("process scope kind must be exact")
        require_id(self.value, "process scope value")


@dataclass(frozen=True, slots=True)
class NetworkRule:
    rule_id: str
    owner: PolicyOwner
    action: NetworkAction
    destinations: tuple[Destination, ...]
    protocols: tuple[NetworkProtocol, ...]
    ports: tuple[PortRange, ...] = ()
    process_scopes: tuple[ProcessScope, ...] = ()
    expires_at_epoch_seconds: int | None = None

    def __post_init__(self) -> None:
        require_id(self.rule_id, "rule_id")
        if not isinstance(cast(object, self.owner), PolicyOwner):
            raise ValueError("owner must be exact")
        if not isinstance(cast(object, self.action), NetworkAction):
            raise ValueError("action must be exact")
        if not self.destinations or any(not isinstance(item, Destination) for item in self.destinations):
            raise ValueError("destinations must contain exact Destination values")
        if not self.protocols or any(not isinstance(item, NetworkProtocol) for item in self.protocols):
            raise ValueError("protocols must contain exact NetworkProtocol values")
        if any(not isinstance(item, PortRange) for item in self.ports):
            raise ValueError("ports must contain exact PortRange values")
        if (
            NetworkProtocol.DNS in self.protocols
            and self.ports
            and all(not (item.start <= 53 <= item.end) for item in self.ports)
        ):
            raise ValueError("DNS rules with ports must include port 53")
        if NetworkProtocol.UNKNOWN in self.protocols:
            raise ValueError("rules cannot authorize unknown protocols")
        if any(not isinstance(scope, ProcessScope) for scope in self.process_scopes):
            raise ValueError("process_scopes must contain exact ProcessScope values")
        scopes = tuple(sorted(set(self.process_scopes), key=lambda item: (item.kind.value, item.value)))
        if self.expires_at_epoch_seconds is not None and (
            type(self.expires_at_epoch_seconds) is not int or self.expires_at_epoch_seconds <= 0
        ):
            raise ValueError("expires_at_epoch_seconds must be positive")
        object.__setattr__(self, "destinations", tuple(sorted(set(self.destinations), key=_destination_key)))
        object.__setattr__(self, "protocols", tuple(sorted(set(self.protocols), key=lambda item: item.value)))
        object.__setattr__(self, "ports", tuple(sorted(set(self.ports), key=lambda item: (item.start, item.end))))
        object.__setattr__(self, "process_scopes", scopes)


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    policy_id: str
    generation: int
    rules: tuple[NetworkRule, ...]
    required_grade: EnforcementGrade
    failure_mode: FailureMode = FailureMode.DENY
    schema_version: str = NETWORK_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported network policy schema version")
        require_id(self.policy_id, "policy_id")
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("generation must be a positive integer")
        if any(not isinstance(item, NetworkRule) for item in self.rules):
            raise ValueError("rules must contain exact NetworkRule values")
        if not isinstance(cast(object, self.required_grade), EnforcementGrade):
            raise ValueError("required_grade must be exact")
        if not isinstance(cast(object, self.failure_mode), FailureMode):
            raise ValueError("failure_mode must be exact")
        identifiers = [item.rule_id for item in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("rule_id values must be unique")
        object.__setattr__(self, "rules", tuple(sorted(self.rules, key=lambda item: item.rule_id)))

    @property
    def digest(self) -> str:
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class NetworkFlowRequest:
    request_id: str
    process_tree: ProcessTreeIdentity
    destination: Destination
    protocol: NetworkProtocol
    port: int
    observed_at_epoch_ms: int
    connected_address: str | None = None
    dns_binding_digest: str | None = None
    schema_version: str = NETWORK_BROKER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_BROKER_SCHEMA_VERSION:
            raise ValueError("unsupported broker schema version")
        require_id(self.request_id, "request_id")
        if not isinstance(self.process_tree, ProcessTreeIdentity):
            raise ValueError("process_tree must be exact")
        if not isinstance(self.destination, Destination):
            raise ValueError("destination must be exact")
        if not isinstance(cast(object, self.protocol), NetworkProtocol):
            raise ValueError("protocol must be exact")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("port must be within 1..65535")
        if type(self.observed_at_epoch_ms) is not int or self.observed_at_epoch_ms <= 0:
            raise ValueError("observed_at_epoch_ms must be positive")
        if self.dns_binding_digest is not None:
            require_digest(self.dns_binding_digest, "dns_binding_digest")
        if self.connected_address is not None:
            try:
                address = ipaddress.ip_address(self.connected_address).compressed
            except ValueError as exc:
                raise ValueError("connected_address must be a canonical IP address") from exc
            object.__setattr__(self, "connected_address", address)


@dataclass(frozen=True, slots=True)
class NetworkDecision:
    request_digest: str
    policy_digest: str
    generation: int
    action: NetworkAction
    rule_ids: tuple[str, ...]
    expires_at_epoch_ms: int

    def __post_init__(self) -> None:
        require_digest(self.request_digest, "request_digest")
        require_digest(self.policy_digest, "policy_digest")
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("generation must be positive")
        if not isinstance(cast(object, self.action), NetworkAction):
            raise ValueError("action must be exact")
        if not self.rule_ids:
            raise ValueError("rule_ids cannot be empty")
        for rule_id in self.rule_ids:
            require_id(rule_id, "rule_id")
        if type(self.expires_at_epoch_ms) is not int or self.expires_at_epoch_ms <= 0:
            raise ValueError("expires_at_epoch_ms must be positive")
        object.__setattr__(self, "rule_ids", tuple(sorted(set(self.rule_ids))))


@dataclass(frozen=True, slots=True)
class BackendAdvertisement:
    backend_id: str
    backend_digest: str
    capabilities: frozenset[BackendCapability]
    maximum_grade: EnforcementGrade
    healthy_until_epoch_ms: int
    schema_version: str = NETWORK_BACKEND_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_BACKEND_SCHEMA_VERSION:
            raise ValueError("unsupported backend schema version")
        require_id(self.backend_id, "backend_id")
        require_digest(self.backend_digest, "backend_digest")
        if not self.capabilities or any(not isinstance(item, BackendCapability) for item in self.capabilities):
            raise ValueError("capabilities must contain exact values")
        if not isinstance(cast(object, self.maximum_grade), EnforcementGrade):
            raise ValueError("maximum_grade must be exact")
        if not grade_required_capabilities(self.maximum_grade).issubset(self.capabilities):
            raise ValueError("maximum_grade exceeds verified capabilities")
        if type(self.healthy_until_epoch_ms) is not int or self.healthy_until_epoch_ms <= 0:
            raise ValueError("healthy_until_epoch_ms must be positive")


@dataclass(frozen=True, slots=True)
class NetworkEvidence:
    flow_id: str
    process_tree_digest: str
    destination_digest: str
    protocol: NetworkProtocol
    port: int
    action: NetworkAction
    policy_digest: str
    backend_digest: str
    grade: EnforcementGrade
    observed_at_epoch_ms: int
    raw_destination: str | None = None
    schema_version: str = NETWORK_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != NETWORK_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported network evidence schema version")
        require_id(self.flow_id, "flow_id")
        for name, value in (
            ("process_tree_digest", self.process_tree_digest),
            ("destination_digest", self.destination_digest),
            ("policy_digest", self.policy_digest),
            ("backend_digest", self.backend_digest),
        ):
            require_digest(value, name)
        if not isinstance(cast(object, self.protocol), NetworkProtocol):
            raise ValueError("protocol must be exact")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("port must be within 1..65535")
        if not isinstance(cast(object, self.action), NetworkAction):
            raise ValueError("action must be exact")
        if not isinstance(cast(object, self.grade), EnforcementGrade):
            raise ValueError("grade must be exact")
        if type(self.observed_at_epoch_ms) is not int or self.observed_at_epoch_ms <= 0:
            raise ValueError("observed_at_epoch_ms must be positive")
        if self.raw_destination is not None:
            raise ValueError("raw destinations require the separate opt-in privacy service")


def canonical_destination(kind: DestinationKind, value: object) -> str:
    """Return one comparison-safe destination or reject ambiguous input."""

    if not isinstance(value, str) or not value or "\x00" in value or value != value.strip():
        raise ValueError("destination must be a trimmed non-empty string")
    if kind is DestinationKind.HOST:
        candidate = value[:-1] if value.endswith(".") else value
        if not candidate or len(candidate) > 253 or any(ord(char) > 127 for char in candidate):
            raise ValueError("host must be pre-normalized ASCII IDNA")
        candidate = candidate.lower()
        labels = candidate.split(".")
        if any(_LABEL.fullmatch(label) is None for label in labels):
            raise ValueError("host contains an invalid label")
        return candidate
    if kind is DestinationKind.IP:
        return ipaddress.ip_address(value).compressed
    if kind is DestinationKind.CIDR:
        return ipaddress.ip_network(value, strict=True).compressed
    if kind is DestinationKind.PRIVATE_CLASS:
        try:
            return PrivateNetworkClass(value).value
        except ValueError as error:
            raise ValueError("unsupported private network class") from error
    raise ValueError("unsupported destination kind")


def classify_private_address(value: str) -> PrivateNetworkClass | None:
    address = ipaddress.ip_address(value)
    if address.is_loopback:
        return PrivateNetworkClass.LOOPBACK
    if address.is_link_local:
        return PrivateNetworkClass.LINK_LOCAL
    if address.is_multicast:
        return PrivateNetworkClass.MULTICAST
    if address.is_unspecified:
        return PrivateNetworkClass.UNSPECIFIED
    if address.is_private:
        return PrivateNetworkClass.PRIVATE
    return None


def canonical_json(value: object) -> str:
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical mapping keys must be strings")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_json_value(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ValueError(f"unsupported canonical value: {type(value).__name__}")


def _destination_key(value: Destination) -> tuple[str, str]:
    return value.kind.value, value.value


def require_id(value: object, name: str) -> None:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a stable identifier")


def require_digest(value: object, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
