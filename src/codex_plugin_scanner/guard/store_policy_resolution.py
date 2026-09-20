"""Policy resolution entry points and memory-pattern composition."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from .store_base import PolicyDecisionLookupResult


class StorePolicyMixin:
    def resolve_policy(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
        consume_one_shot: bool = True,
        exact_command_sha256: str | None = None,
    ) -> str | None:
        lookup = self.resolve_policy_decision_lookup_with_memory_pattern(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            memory_command=memory_command,
            memory_artifact_type=memory_artifact_type,
            memory_artifact_name=memory_artifact_name,
            consume_one_shot=consume_one_shot,
            exact_command_sha256=exact_command_sha256,
        )
        decision = lookup["decision"]
        return str(decision["action"]) if decision is not None else None

    def resolve_policy_decision_lookup_with_memory_pattern(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        *,
        memory_command: str | None = None,
        memory_artifact_type: str | None = None,
        memory_artifact_name: str | None = None,
        consume_one_shot: bool = True,
        exact_command_sha256: str | None = None,
    ) -> PolicyDecisionLookupResult:
        from . import store_policy as _policy

        direct_lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
            exact_command_sha256=exact_command_sha256,
        )
        candidate_lookups = [direct_lookup]
        if consume_one_shot and (
            direct_lookup["decision"] is not None or direct_lookup.get("ignored_local_integrity") is not None
        ):
            return direct_lookup
        if _policy._memory_artifact_is_shell_command(memory_artifact_type, memory_artifact_name):
            exact_command_artifact_ids = (
                _policy.build_exact_shell_command_memory_artifact_id(memory_command),
                _policy.build_exact_command_memory_artifact_id(memory_command),
            )
            for exact_command_artifact_id in _policy._distinct_non_null(exact_command_artifact_ids):
                if exact_command_artifact_id == artifact_id:
                    continue
                exact_command_lookup = self.resolve_policy_decision_lookup(
                    harness,
                    exact_command_artifact_id,
                    artifact_hash=artifact_hash,
                    workspace=workspace,
                    publisher=publisher,
                    now=now,
                    runtime_exact_match_context=runtime_exact_match_context,
                    consume_one_shot=consume_one_shot,
                    exact_command_sha256=exact_command_sha256,
                )
                candidate_lookups.append(exact_command_lookup)
                if consume_one_shot and (
                    exact_command_lookup["decision"] is not None
                    or exact_command_lookup.get("ignored_local_integrity") is not None
                ):
                    return exact_command_lookup
        memory_pattern = _policy.build_memory_pattern_fingerprint(
            command=memory_command,
            artifact_type=memory_artifact_type,
            artifact_id=artifact_id,
            artifact_name=memory_artifact_name,
            harness=harness,
        )
        if memory_pattern is None:
            return _policy._most_restrictive_policy_lookup(candidate_lookups)
        memory_artifact_id = f"memory:{harness}:{memory_pattern.kind}:{memory_pattern.fingerprint}"
        if memory_artifact_id == artifact_id:
            return _policy._most_restrictive_policy_lookup(candidate_lookups)
        memory_lookup = self.resolve_policy_decision_lookup(
            harness,
            memory_artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
            exact_command_sha256=exact_command_sha256,
        )
        candidate_lookups.append(memory_lookup)
        if consume_one_shot:
            return (
                memory_lookup
                if (memory_lookup["decision"] is not None or memory_lookup.get("ignored_local_integrity") is not None)
                else direct_lookup
            )
        return _policy._most_restrictive_policy_lookup(candidate_lookups)

    def resolve_policy_decision(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
        exact_command_sha256: str | None = None,
    ) -> dict[str, object] | None:
        lookup = self.resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
            exact_command_sha256=exact_command_sha256,
        )
        return lookup["decision"]
