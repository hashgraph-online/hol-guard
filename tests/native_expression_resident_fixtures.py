"""Genuine signed expression sources for staged native resident proof.

Only source admission is staged at the existing atomic store boundary. This
fixture does not certify ordinary sync, default capabilities, or installed use.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_expressions import NATIVE_COMMAND_EXPRESSIONS_FEATURE
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_scoped_resident_fixtures import explicitly_negotiated_test_status, prepare_store
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

COMMAND = "printf 'NativeBlocked'"
EXACT_COMMAND = "echo 'Exact Native'"
ARTIFACT = "codex:project:Bash"
WORKSPACE_ID = "00000000-0000-4000-8000-000000000062"


@dataclass(frozen=True, slots=True)
class ExpressionSource:
    bundle_hash: str
    block_expires_at: datetime


def configure_expression_fixture_policy(
    store: GuardStore, *, unknown_publisher_action: Literal["allow", "review"] = "allow"
) -> None:
    # The controlled command baseline must not inherit the ordinary unknown-
    # publisher Review or subprocess Warn floor. The preflight checks other
    # configured risk defaults. Intrinsic/managed composition is not mocked.
    (store.guard_home / "config.toml").write_text(
        'mode = "enforce"\ndefault_action = "allow"\n'
        f'unknown_publisher_action = "{unknown_publisher_action}"\n'
        'subprocess_action = "allow"\n[harnesses]\ncodex = "allow"\n',
        encoding="utf-8",
    )


def prepare_expression_store(tmp_path: Path) -> tuple[GuardStore, Path]:
    store, workspace = prepare_store(tmp_path)
    configure_expression_fixture_policy(store)
    return store, workspace


def expression_test_status() -> NativeRuntimeStatus:
    status = explicitly_negotiated_test_status()
    assert status.capabilities is not None
    return replace(
        status,
        capabilities=replace(
            status.capabilities,
            features=tuple(sorted({*status.capabilities.features, NATIVE_COMMAND_EXPRESSIONS_FEATURE})),
        ),
    )


def publish_expression_source(
    store: GuardStore, workspace: Path, *, block_lifetime_seconds: float = 24
) -> ExpressionSource:
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(seconds=block_lifetime_seconds)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id=WORKSPACE_ID)

    def condition(operator: str, value: str) -> dict[str, object]:
        return {"field": "command", "operator": operator, "value": value, "caseSensitive": True}

    def rule(rule_id: str, effect: str, commands: dict[str, object], *, exact: bool = False) -> dict[str, object]:
        match: dict[str, object] = {
            "harnesses": ["codex"],
            "artifacts": [ARTIFACT],
            "workspaces": [str(workspace)],
            "commands": commands,
        }
        if exact:
            match["exactCommand"] = {
                "contractVersion": "guard.exact-command.v1",
                "sha256": hashlib.sha256(EXACT_COMMAND.encode("utf-8")).hexdigest(),
            }
        return {
            "id": rule_id,
            "enabled": True,
            "effect": effect,
            "match": match,
            "lifetime": {
                "mode": "permanent" if exact else "until",
                "expiresAt": None if exact else expiry.isoformat().replace("+00:00", "Z"),
            },
            "provenance": {"source": "cloud", "createdAt": now.isoformat().replace("+00:00", "Z")},
        }

    generic: dict[str, object] = {
        "id": "unrelated.generic",
        "enabled": True,
        "effect": "allow",
        "match": {"harnesses": ["codex"], "artifacts": ["synthetic-unrelated"]},
        "lifetime": {"mode": "permanent", "expiresAt": None},
        "provenance": {"source": "cloud", "createdAt": now.isoformat().replace("+00:00", "Z")},
    }
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.expression-policy", "name": "Synthetic expressions", "revision": 7},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "allow"},
            "rules": [
                generic,
                rule(
                    "block.expression",
                    "block",
                    {
                        "combinator": "all",
                        "conditions": [
                            condition("startsWith", "printf"),
                            condition("contains", "Native"),
                            condition("endsWith", "Blocked'"),
                        ],
                    },
                ),
                rule(
                    "review.exact-expression",
                    "review",
                    {"combinator": "all", "conditions": [condition("contains", "Exact Native")]},
                    exact=True,
                ),
            ],
        },
    }
    bundle = _signed_bundle(private, key, payload_base=payload, rollout_state="enforcing", bundle_version=9)
    bundle["workspaceId"] = WORKSPACE_ID
    bundle["issuedAt"] = now.isoformat().replace("+00:00", "Z")
    bundle["expiresAt"] = (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(
        private.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("ascii")
    store.set_sync_payload(
        "oauth_local_credentials", {"workspace_id": WORKSPACE_ID}, now.isoformat().replace("+00:00", "Z")
    )
    # The complete signed source is real. Its admission is explicitly staged:
    # only the independent generic rule is represented in the generic cache.
    applied = store.apply_policy_bundle_authority(
        [
            PolicyDecision(
                harness="codex",
                scope="artifact",
                action="allow",
                artifact_id="synthetic-unrelated",
                owner="unrelated.generic",
                source="policy-bundle-canonical",
            )
        ],
        now.isoformat().replace("+00:00", "Z"),
        policy_bundle=bundle,
        policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id=WORKSPACE_ID),
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "bundleVersion": 9, "status": "validated"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )
    assert applied is not None
    captured = read_native_policy_authority_inputs(store, now=now.timestamp())
    assert len(captured.authority.command_expressions) == 2
    assert {identity.rule_id for _, identity in captured.rule_identities} == {
        "unrelated.generic",
        "block.expression",
        "review.exact-expression",
    }
    assert all(row["artifact_id"] != ARTIFACT for row in store.list_policy_decisions())
    bundle_hash = bundle["bundleHash"]
    assert isinstance(bundle_hash, str)
    return ExpressionSource(bundle_hash, expiry)
