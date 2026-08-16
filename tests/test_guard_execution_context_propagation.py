"""Tests for execution-context propagation (ExecutionContextLink + derive_child_link)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest
from codex_plugin_scanner.guard.runtime.execution_context_propagation import (
    _EXECUTION_CONTEXT_LINK_DOMAIN,
    _MAX_DEPTH,
    _MAX_FIELD_LENGTH,
    construct_execution_context_link,
    derive_child_link,
)

# ── Construction ──────────────────────────────────────────────────────────


class TestConstructExecutionContextLink:
    """Basic construction and validation of ExecutionContextLink."""

    def test_root_link_defaults(self) -> None:
        link = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
        )
        assert link.is_root is True
        assert link.is_retry is False
        assert link.depth == 0
        assert link.parent_correlation_id is None
        assert link.retry_of_correlation_id is None
        assert link.root_id == "root-1"
        assert link.attempt_nonce == "nonce-a"
        assert link.correlation_id == "root-1"
        assert len(link.continuation_digest) == 64

    def test_root_link_fresh_digest(self) -> None:
        link = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
        )
        payload: dict = {
            "correlation_id": "root-1",
            "root_id": "root-1",
            "attempt_nonce": "nonce-a",
            "parent_correlation_id": None,
            "retry_of_correlation_id": None,
            "depth": 0,
        }
        expected = framed_digest(_EXECUTION_CONTEXT_LINK_DOMAIN, payload)
        assert link.continuation_digest == expected

    def test_digest_stability_same_inputs(self) -> None:
        link_a = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
        )
        link_b = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
        )
        assert link_a.continuation_digest == link_b.continuation_digest

    def test_root_link_accepts_custom_digest(self) -> None:
        fake_digest = "0" * 64
        link = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
            continuation_digest=fake_digest,
        )
        assert link.continuation_digest == fake_digest

    def test_root_link_with_parent(self) -> None:
        link = construct_execution_context_link(
            correlation_id="child-1",
            root_id="root-1",
            attempt_nonce="nonce-b",
            parent_correlation_id="parent-1",
            depth=1,
        )
        assert link.is_root is False
        assert link.depth == 1
        assert link.parent_correlation_id == "parent-1"

    def test_root_link_with_retry(self) -> None:
        link = construct_execution_context_link(
            correlation_id="retry-1",
            root_id="root-1",
            attempt_nonce="nonce-c",
            retry_of_correlation_id="original-1",
        )
        assert link.is_retry is True
        assert link.retry_of_correlation_id == "original-1"

    def test_immutability(self) -> None:
        link = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
        )
        with pytest.raises(FrozenInstanceError):
            link.depth = 99

    def test_depth_zero_is_valid(self) -> None:
        link = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
            depth=0,
        )
        assert link.depth == 0

    def test_max_depth_32_is_valid(self) -> None:
        link = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
            depth=32,
        )
        assert link.depth == 32

    def test_depth_33_rejected(self) -> None:
        with pytest.raises(ValueError, match="depth must be at most 32"):
            construct_execution_context_link(
                correlation_id="r",
                root_id="r",
                attempt_nonce="n",
                depth=33,
            )


# ── Validation ────────────────────────────────────────────────────────────


class TestValidation:
    """Field-level validation on ExecutionContextLink."""

    @pytest.mark.parametrize(
        "label",
        [
            "correlation_id",
            "parent_correlation_id",
            "retry_of_correlation_id",
            "attempt_nonce",
            "root_id",
        ],
    )
    def test_empty_strings_rejected(self, label: str) -> None:
        kwargs: dict = {
            "correlation_id": "root-1",
            "root_id": "root-1",
            "attempt_nonce": "nonce-a",
        }
        kwargs[label] = ""
        with pytest.raises(ValueError):
            construct_execution_context_link(**kwargs)

    @pytest.mark.parametrize(
        "label",
        [
            "correlation_id",
            "parent_correlation_id",
            "retry_of_correlation_id",
            "attempt_nonce",
            "root_id",
        ],
    )
    def test_too_long_strings_rejected(self, label: str) -> None:
        long_str = "x" * (_MAX_FIELD_LENGTH + 1)
        kwargs: dict = {
            "correlation_id": long_str if label == "correlation_id" else "root-1",
            "root_id": "root-1",
            "attempt_nonce": "nonce-a",
        }
        if label == "parent_correlation_id":
            kwargs["parent_correlation_id"] = long_str
        elif label == "retry_of_correlation_id":
            kwargs["retry_of_correlation_id"] = long_str
        elif label == "attempt_nonce":
            kwargs["attempt_nonce"] = long_str
        elif label == "root_id":
            kwargs["root_id"] = long_str
        with pytest.raises(ValueError, match="at most 128"):
            construct_execution_context_link(**kwargs)

    def test_invalid_sha256_digest_rejected(self) -> None:
        with pytest.raises(ValueError, match="continuation_digest"):
            construct_execution_context_link(
                correlation_id="root-1",
                root_id="root-1",
                attempt_nonce="nonce-a",
                continuation_digest="not-a-sha256",
            )

    def test_uppercase_sha256_rejected(self) -> None:
        with pytest.raises(ValueError, match="continuation_digest"):
            construct_execution_context_link(
                correlation_id="root-1",
                root_id="root-1",
                attempt_nonce="nonce-a",
                continuation_digest="a" * 63 + "A",
            )

    def test_negative_depth_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            construct_execution_context_link(
                correlation_id="r",
                root_id="r",
                attempt_nonce="n",
                depth=-1,
            )

    def test_bool_depth_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            construct_execution_context_link(
                correlation_id="r",
                root_id="r",
                attempt_nonce="n",
                depth=True,  # type: ignore[arg-type]
            )


# ── derive_child_link ─────────────────────────────────────────────────────


class TestDeriveChildLink:
    """Parent → child linkage via derive_child_link."""

    def test_simple_child(self) -> None:
        parent = construct_execution_context_link(
            correlation_id="root-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
            depth=0,
        )
        child = derive_child_link(parent)
        assert child.root_id == parent.root_id
        assert child.depth == 1
        assert child.parent_correlation_id == parent.correlation_id
        assert child.retry_of_correlation_id is None
        assert child.is_root is False
        assert child.is_retry is False

    def test_child_preserves_root(self) -> None:
        grandparent = construct_execution_context_link(
            correlation_id="gp",
            root_id="gp-root",
            attempt_nonce="nonce-gp",
            depth=0,
        )
        parent = derive_child_link(grandparent, child_correlation_id="p")
        child = derive_child_link(parent, child_correlation_id="c")
        assert child.root_id == "gp-root"
        assert child.depth == 2

    def test_retry_child(self) -> None:
        parent = construct_execution_context_link(
            correlation_id="original-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
            depth=1,
        )
        retry_child = derive_child_link(parent, retry=True)
        assert retry_child.retry_of_correlation_id == parent.correlation_id
        assert retry_child.depth == 2
        assert retry_child.root_id == parent.root_id
        assert retry_child.is_retry is True

    def test_non_retry_child_clears_retry_linkage(self) -> None:
        parent = construct_execution_context_link(
            correlation_id="original-1",
            root_id="root-1",
            attempt_nonce="nonce-a",
            depth=1,
            retry_of_correlation_id="earlier-0",
        )
        child = derive_child_link(parent, retry=False)
        assert child.retry_of_correlation_id is None

    def test_depth_exceeded_raises(self) -> None:
        link = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
            depth=_MAX_DEPTH,  # 32
        )
        with pytest.raises(ValueError, match="exceeds maximum"):
            derive_child_link(link)

    def test_child_correlation_id_custom(self) -> None:
        parent = construct_execution_context_link(
            correlation_id="root",
            root_id="root",
            attempt_nonce="n",
        )
        child = derive_child_link(
            parent,
            child_correlation_id="my-custom-id",
        )
        assert child.correlation_id == "my-custom-id"

    def test_child_attempt_nonce_custom(self) -> None:
        parent = construct_execution_context_link(
            correlation_id="root",
            root_id="root",
            attempt_nonce="n",
        )
        child = derive_child_link(
            parent,
            child_attempt_nonce="custom-nonce",
        )
        assert child.attempt_nonce == "custom-nonce"

    def test_chained_parent_child_retry(self) -> None:
        """Construct a chain: root → child → child(retry) → grandchild."""
        root = construct_execution_context_link(
            correlation_id="root",
            root_id="root",
            attempt_nonce="n0",
        )
        child1 = derive_child_link(root, child_correlation_id="c1")
        assert child1.depth == 1
        assert child1.parent_correlation_id == "root"

        retry_of_c1 = derive_child_link(child1, retry=True, child_correlation_id="retry-of-c1")
        assert retry_of_c1.depth == 2
        assert retry_of_c1.retry_of_correlation_id == "c1"
        assert retry_of_c1.root_id == "root"

        grandchild = derive_child_link(retry_of_c1, child_correlation_id="gc")
        assert grandchild.depth == 3
        assert grandchild.root_id == "root"
        assert grandchild.retry_of_correlation_id is None

    def test_digest_changes_with_different_inputs(self) -> None:
        root = construct_execution_context_link(
            correlation_id="root",
            root_id="root",
            attempt_nonce="n0",
        )
        root2 = construct_execution_context_link(
            correlation_id="root2",
            root_id="root",
            attempt_nonce="n0",
        )
        assert root.continuation_digest != root2.continuation_digest


# ── Freeze / immutability ────────────────────────────────────────────────


class TestFrozenProperties:
    """ExecutionContextLink is a frozen dataclass with slots."""

    def test_frozen_dataclass(self) -> None:
        link = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
        )
        fields = link.__dataclass_fields__
        assert isinstance(fields, dict)
        assert "correlation_id" in fields
        assert "continuation_digest" in fields

    def test_comparison(self) -> None:
        a = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
        )
        b = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
        )
        assert a == b
        a2 = construct_execution_context_link(
            correlation_id="r",
            root_id="r2",
            attempt_nonce="n",
        )
        assert a != a2

    def test_hashable(self) -> None:
        link = construct_execution_context_link(
            correlation_id="r",
            root_id="r",
            attempt_nonce="n",
        )
        s: set = {link}
        assert link in s


def test_chained_child_ids_stay_bounded() -> None:
    from codex_plugin_scanner.guard.runtime.execution_context_propagation import (
        construct_execution_context_link,
        derive_child_link,
    )

    link = construct_execution_context_link(
        correlation_id="root",
        root_id="root",
        attempt_nonce="n0",
        depth=0,
    )
    for _ in range(10):
        link = derive_child_link(link)
    assert len(link.correlation_id) <= 64
    assert len(link.attempt_nonce) <= 64
