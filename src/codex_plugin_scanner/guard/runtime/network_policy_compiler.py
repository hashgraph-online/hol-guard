"""Atomic generation management for compiled network policies."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkPolicy, canonical_json


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    policy: NetworkPolicy
    artifact: bytes

    @property
    def digest(self) -> str:
        return self.policy.digest


class AtomicPolicyCompiler:
    """Stage immutable policy bytes, then activate them with a digest CAS token."""

    def __init__(self) -> None:
        self._active: CompiledPolicy | None = None
        self._staged: CompiledPolicy | None = None

    @property
    def active(self) -> CompiledPolicy | None:
        return self._active

    @property
    def staged(self) -> CompiledPolicy | None:
        return self._staged

    def stage(self, policy: NetworkPolicy) -> CompiledPolicy:
        if self._active is not None and policy.generation <= self._active.policy.generation:
            raise ValueError("staged generation must exceed active generation")
        if self._staged is not None and policy.generation <= self._staged.policy.generation:
            raise ValueError("staged generation must increase monotonically")
        compiled = CompiledPolicy(policy=policy, artifact=canonical_json(policy).encode("utf-8"))
        self._staged = compiled
        return compiled

    def activate(self, expected_digest: str) -> CompiledPolicy:
        staged = self._staged
        if staged is None:
            raise RuntimeError("no staged policy")
        if staged.digest != expected_digest:
            raise RuntimeError("staged policy digest mismatch")
        self._active = staged
        self._staged = None
        return staged

    def discard(self, expected_digest: str) -> bool:
        if self._staged is None or self._staged.digest != expected_digest:
            return False
        self._staged = None
        return True
