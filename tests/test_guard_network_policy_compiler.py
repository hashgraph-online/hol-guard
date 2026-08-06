from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_policy_compiler import AtomicPolicyCompiler
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade, NetworkPolicy


def _policy(generation: int) -> NetworkPolicy:
    return NetworkPolicy(
        policy_id="policy.local",
        generation=generation,
        rules=(),
        required_grade=EnforcementGrade.UNAVAILABLE,
    )


def test_policy_activation_is_atomic_and_digest_bound() -> None:
    compiler = AtomicPolicyCompiler()
    staged = compiler.stage(_policy(1))

    assert compiler.active is None
    assert staged.artifact
    with pytest.raises(RuntimeError, match="digest mismatch"):
        compiler.activate("f" * 64)
    assert compiler.active is None

    active = compiler.activate(staged.digest)
    assert active == staged
    assert compiler.staged is None


def test_policy_generations_never_roll_back_or_replace_newer_stage() -> None:
    compiler = AtomicPolicyCompiler()
    first = compiler.stage(_policy(1))
    compiler.activate(first.digest)
    second = compiler.stage(_policy(3))

    with pytest.raises(ValueError, match="increase monotonically"):
        compiler.stage(_policy(2))
    assert compiler.staged == second
    assert not compiler.discard("0" * 64)
    assert compiler.discard(second.digest)

    with pytest.raises(ValueError, match="exceed active"):
        compiler.stage(_policy(1))
