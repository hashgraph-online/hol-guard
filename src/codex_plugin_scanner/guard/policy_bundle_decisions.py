"""Canonical materialization of signed policy-bundle rules."""

from __future__ import annotations

from .memory_pattern_fingerprint import build_exact_shell_command_memory_artifact_id
from .models import PolicyDecision
from .policy_bundle_parser import (
    POLICY_BUNDLE_BROWSER_SCOPE_KEYS,
    POLICY_BUNDLE_DEFAULT_ENVIRONMENTS,
    POLICY_BUNDLE_RULE_ACTIONS,
    POLICY_BUNDLE_RULE_MATCHER_FAMILIES,
    non_empty_string,
)

_FAMILY_REPRESENTABLE_SCOPE_KEYS = frozenset(
    {
        "agents",
        "devices",
        "environments",
        "harnesses",
        "locations",
    }
)
_NON_SELECTOR_RULE_KEYS = (
    frozenset(
        {
            "action",
            "artifactId",
            "artifactType",
            "artifact_id",
            "auditEventIds",
            "expiresAt",
            "matcher",
            "matcherFamilies",
            "reason",
            "ruleId",
            "scope",
            "sourceDecisionId",
            "sourceLocalRequestId",
            "sourceReceiptId",
            "sourceReceiptIds",
            "sourceSuggestionId",
        }
    )
    | POLICY_BUNDLE_BROWSER_SCOPE_KEYS
)
_ARTIFACT_TYPE_FAMILY = {
    "file_read_request": "file-read",
    "package_request": "package-request",
    "prompt_request": "prompt",
    "tool_action_request": "tool-action",
}


def _policy_bundle_rule_matcher_families(rule: dict[str, object]) -> list[str]:
    if "matcherFamilies" in rule:
        explicit = rule.get("matcherFamilies")
        if not isinstance(explicit, list) or any(
            not isinstance(family, str) or not family.strip() or family not in POLICY_BUNDLE_RULE_MATCHER_FAMILIES
            for family in explicit
        ):
            return []
        return list(dict.fromkeys(explicit))

    derived: list[str] = []
    scope = rule.get("scope")
    if isinstance(scope, dict):
        if isinstance(scope.get("ecosystems"), list) and scope["ecosystems"]:
            derived.append("package-request")
        if non_empty_string(scope.get("mcp")) is not None or non_empty_string(scope.get("tool")) is not None:
            derived.append("mcp")
        if non_empty_string(scope.get("command")) is not None:
            derived.append("tool-action")
        if non_empty_string(scope.get("path")) is not None or non_empty_string(scope.get("secretType")) is not None:
            derived.append("file-read")
    artifact_type = non_empty_string(rule.get("artifactType"))
    artifact_type_family = _ARTIFACT_TYPE_FAMILY.get(artifact_type or "")
    if artifact_type_family is not None:
        derived.append(artifact_type_family)
    return list(dict.fromkeys(family for family in derived if family in POLICY_BUNDLE_RULE_MATCHER_FAMILIES))


def _has_constraint(value: object) -> bool:
    """Treat malformed values as constraints so materialization fails closed."""

    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list, set, tuple)):
        return bool(value)
    return True


def _rule_scope_is_exactly_representable(
    rule: dict[str, object],
    *,
    identity_scope_keys: frozenset[str] = frozenset(),
) -> bool:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return False
    for key, value in scope.items():
        if key in identity_scope_keys:
            if non_empty_string(value) is None:
                return False
            continue
        if key not in _FAMILY_REPRESENTABLE_SCOPE_KEYS:
            if _has_constraint(value):
                return False
            continue
        if not isinstance(value, list):
            return False
        if any(not isinstance(item, str) or not item.strip() for item in value):
            return False
    return True


def _rule_has_unknown_constraints(rule: dict[str, object]) -> bool:
    return any(key not in _NON_SELECTOR_RULE_KEYS and _has_constraint(value) for key, value in rule.items())


def _family_rule_metadata_is_exactly_representable(rule: dict[str, object]) -> bool:
    if _rule_has_unknown_constraints(rule):
        return False

    matcher = rule.get("matcher")
    if matcher is not None:
        if not isinstance(matcher, dict):
            return False
        # Exact matcher identities are materialized separately. Any remaining
        # matcher field is a selector PolicyDecision cannot encode.
        if any(_has_constraint(value) for value in matcher.values()):
            return False

    artifact_type = non_empty_string(rule.get("artifactType"))
    return artifact_type is None or artifact_type in _ARTIFACT_TYPE_FAMILY


def _exact_rule_is_exactly_representable(rule: dict[str, object]) -> bool:
    declared_commands = _policy_bundle_rule_declared_commands(rule)
    if declared_commands is None or len(declared_commands) > 1:
        # Differing matcher/scope commands are an ambiguous conjunction. A
        # client must not choose one alias and silently discard the other.
        return False
    exact_command = declared_commands[0] if declared_commands else None
    declared_artifact_ids = _policy_bundle_rule_declared_artifact_ids(rule)
    if declared_artifact_ids is None:
        return False
    # The command fingerprint is narrower than a separately advertised
    # artifact label. Materialize only that derived identity; never emit the
    # declared artifact aliases as additional permissions.
    if exact_command is None and len(declared_artifact_ids) != 1:
        # Treat differing camel/snake/top-level/matcher aliases as an
        # ambiguous conjunction, never as multiple independent permissions.
        return False
    identity_scope_keys = frozenset({"command"}) if exact_command is not None else frozenset()
    if not _rule_scope_is_exactly_representable(rule, identity_scope_keys=identity_scope_keys):
        return False
    if _rule_has_unknown_constraints(rule):
        return False

    matcher = rule.get("matcher")
    if matcher is None:
        return True
    if not isinstance(matcher, dict):
        return False
    identity_matcher_keys = {"artifactId", "artifact_id"}
    if exact_command is not None:
        # A top-level artifact label is metadata for some portal command
        # rules, but a matcher-level artifact is an additional selector.
        identity_matcher_keys = {"command", "tool"}
    for key, value in matcher.items():
        if key not in identity_matcher_keys and _has_constraint(value):
            return False
        if key == "tool" and non_empty_string(value) not in {"bash", "shell"}:
            return False
    return True


def policy_bundle_rule_saved_decision_families(rule: dict[str, object]) -> list[str]:
    """Return rule families that can be represented without broadening scope."""

    families = _policy_bundle_rule_matcher_families(rule)
    if not families:
        return []

    declared_commands = _policy_bundle_rule_declared_commands(rule)
    declared_artifact_ids = _policy_bundle_rule_declared_artifact_ids(rule)
    # An exact artifact or command is persisted at artifact scope. Emitting a
    # family row as well would silently turn that exact grant into a broad one.
    # Malformed identity aliases also fail closed instead of disappearing and
    # exposing a family-only interpretation of the same rule.
    if declared_commands is None or declared_artifact_ids is None or declared_commands or declared_artifact_ids:
        return []
    if not _rule_scope_is_exactly_representable(rule):
        return []
    if not _family_rule_metadata_is_exactly_representable(rule):
        return []

    artifact_type = non_empty_string(rule.get("artifactType"))
    if artifact_type is not None:
        artifact_family = _ARTIFACT_TYPE_FAMILY[artifact_type]
        families = [family for family in families if family == artifact_family]

    # A matcher-family-only package rule is also used for policy-graph defaults
    # that are not saved package authority. Require the explicit artifact type
    # before producing a package-wide saved decision.
    if artifact_type != "package_request":
        families = [family for family in families if family != "package-request"]
    return families


def _policy_bundle_rule_matches_local_scope(
    rule: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> bool:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return False
    devices = scope.get("devices")
    if isinstance(devices, list) and devices and device_id not in devices and device_name not in devices:
        return False
    environments = scope.get("environments")
    if not isinstance(environments, list) or not environments:
        return True
    return any(isinstance(item, str) and item in POLICY_BUNDLE_DEFAULT_ENVIRONMENTS for item in environments)


def _policy_bundle_rule_locations(rule: dict[str, object]) -> list[str]:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return []
    locations = scope.get("locations")
    if not isinstance(locations, list):
        return []
    return [item.strip() for item in locations if isinstance(item, str) and item.strip()]


def _policy_bundle_non_empty_exact_command(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _policy_bundle_rule_exact_command(rule: dict[str, object]) -> str | None:
    matcher = rule.get("matcher")
    if isinstance(matcher, dict):
        command = _policy_bundle_non_empty_exact_command(matcher.get("command"))
        if command is not None:
            return command
    scope = rule.get("scope")
    if isinstance(scope, dict):
        return _policy_bundle_non_empty_exact_command(scope.get("command"))
    return None


def _policy_bundle_rule_declared_commands(rule: dict[str, object]) -> list[str] | None:
    """Return command aliases, or ``None`` when a present alias is malformed."""

    commands: list[str] = []
    for source in (rule.get("matcher"), rule.get("scope")):
        if not isinstance(source, dict) or "command" not in source:
            continue
        command = _policy_bundle_non_empty_exact_command(source.get("command"))
        if command is None:
            return None
        commands.append(command)
    return list(dict.fromkeys(commands))


def _policy_bundle_rule_declared_artifact_ids(rule: dict[str, object]) -> list[str] | None:
    artifact_ids: list[str] = []
    matcher = rule.get("matcher")
    if isinstance(matcher, dict):
        for key in ("artifactId", "artifact_id"):
            if key not in matcher:
                continue
            value = non_empty_string(matcher.get(key))
            if value is None:
                return None
            artifact_ids.append(value)
    for key in ("artifactId", "artifact_id"):
        if key not in rule:
            continue
        value = non_empty_string(rule.get(key))
        if value is None:
            return None
        artifact_ids.append(value)
    return list(dict.fromkeys(artifact_ids))


def _policy_bundle_rule_exact_artifact_ids(rule: dict[str, object]) -> list[str]:
    exact_command_artifact_id = build_exact_shell_command_memory_artifact_id(_policy_bundle_rule_exact_command(rule))
    if exact_command_artifact_id is not None:
        return [exact_command_artifact_id]
    return _policy_bundle_rule_declared_artifact_ids(rule) or []


def _policy_bundle_rule_expires_at(
    rule: dict[str, object],
    policy_bundle: dict[str, object],
) -> str | None:
    return non_empty_string(rule.get("expiresAt")) or non_empty_string(policy_bundle.get("expiresAt"))


def _policy_bundle_rule_source_metadata(rule: dict[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    for key in ("sourceDecisionId", "sourceSuggestionId", "ruleId"):
        value = non_empty_string(rule.get(key))
        if value is not None:
            metadata[key] = value
    for key in ("sourceReceiptIds", "auditEventIds"):
        value = rule.get(key)
        if isinstance(value, list):
            items = [item for item in (non_empty_string(entry) for entry in value) if item is not None]
            if items:
                metadata[key] = items
    return metadata


def _policy_bundle_rule_reason(rule: dict[str, object], rule_id: str) -> str:
    reason = non_empty_string(rule.get("reason")) or f"Matched Guard Cloud rule {rule_id}."
    source_metadata = _policy_bundle_rule_source_metadata(rule)
    diagnostic_ids = [
        f"{key}={value}" for key, value in source_metadata.items() if isinstance(value, str) and key != "ruleId"
    ]
    if diagnostic_ids:
        return f"{reason} ({'; '.join(diagnostic_ids)})"
    return reason


def _policy_bundle_rule_harnesses(rule: dict[str, object]) -> list[str]:
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return ["*"]
    selector_sets: list[set[str]] = []
    for key in ("harnesses", "agents"):
        current = scope.get(key)
        if not isinstance(current, list) or not current:
            continue
        normalized = {item.strip().lower() for item in current if isinstance(item, str) and item.strip()}
        if "custom" in normalized:
            # ``custom`` denotes a portal-side harness class, not every local
            # harness. PolicyDecision cannot encode that class without turning
            # it into wildcard authority.
            return []
        selector_sets.append(normalized)
    if not selector_sets:
        return ["*"]
    selected = set.intersection(*selector_sets)
    return sorted(selected)


def _policy_bundle_rule_has_browser_scope(rule: dict[str, object]) -> bool:
    """Return whether a rule has a browser constraint unsafe to materialize broadly."""

    for source in (rule, rule.get("scope")):
        if not isinstance(source, dict):
            continue
        for key in POLICY_BUNDLE_BROWSER_SCOPE_KEYS:
            if key not in source:
                continue
            # An empty list is the only schema-valid no-op. Treat every other
            # present value, including malformed scalars/mappings, as a
            # browser constraint that PolicyDecision cannot encode.
            if source.get(key) != []:
                return True
    return False


def build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    """Materialize the exact persisted decisions authorized by a policy bundle."""

    decisions: list[PolicyDecision] = []
    rules = policy_bundle.get("rules")
    if not isinstance(rules, list):
        return decisions
    for item in rules:
        if not isinstance(item, dict):
            continue
        if not _policy_bundle_rule_matches_local_scope(item, device_id=device_id, device_name=device_name):
            continue
        action = item.get("action")
        if action == "ignore" or action not in POLICY_BUNDLE_RULE_ACTIONS:
            continue
        if _policy_bundle_rule_has_browser_scope(item):
            continue
        rule_id = non_empty_string(item.get("ruleId")) or "bundle-rule"
        reason = _policy_bundle_rule_reason(item, rule_id)
        locations = _policy_bundle_rule_locations(item)
        expires_at = _policy_bundle_rule_expires_at(item, policy_bundle)
        exact_artifact_ids = _policy_bundle_rule_exact_artifact_ids(item)
        if exact_artifact_ids and _exact_rule_is_exactly_representable(item):
            for harness in _policy_bundle_rule_harnesses(item):
                for artifact_id in exact_artifact_ids:
                    if locations:
                        for location in locations:
                            decisions.append(
                                PolicyDecision(
                                    harness=harness,
                                    scope="workspace",
                                    action=action,
                                    artifact_id=artifact_id,
                                    workspace=location,
                                    reason=reason,
                                    owner=rule_id,
                                    source="policy-bundle",
                                    expires_at=expires_at,
                                )
                            )
                    else:
                        decisions.append(
                            PolicyDecision(
                                harness=harness,
                                scope="artifact",
                                action=action,
                                artifact_id=artifact_id,
                                reason=reason,
                                owner=rule_id,
                                source="policy-bundle",
                                expires_at=expires_at,
                            )
                        )
        matcher_families = policy_bundle_rule_saved_decision_families(item)
        if not matcher_families:
            continue
        for harness in _policy_bundle_rule_harnesses(item):
            for family in matcher_families:
                if locations:
                    for location in locations:
                        decisions.append(
                            PolicyDecision(
                                harness=harness,
                                scope="workspace",
                                action=action,
                                artifact_id=f"family:{family}",
                                workspace=location,
                                reason=reason,
                                owner=rule_id,
                                source="policy-bundle",
                                expires_at=expires_at,
                            )
                        )
                else:
                    decisions.append(
                        PolicyDecision(
                            harness=harness,
                            scope="harness",
                            action=action,
                            artifact_id=f"family:{family}",
                            reason=reason,
                            owner=rule_id,
                            source="policy-bundle",
                            expires_at=expires_at,
                        )
                    )
    return decisions
