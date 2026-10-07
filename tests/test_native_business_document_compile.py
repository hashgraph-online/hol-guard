"""Whole-source identity across the real native document compiler boundary."""

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_business_document_compile import (
    COMPILE_CAPABILITY,
    compile_business_policy_document,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_document import canonical_policy_document_bytes, policy_document_digest
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml


def document(revision: int = 1, *, scoped: bool = False):
    value = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "policy.fixture", "name": "Source fixture", "revision": revision},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "block"},
            "rules": [
                {
                    "id": "rule.mail",
                    "enabled": True,
                    "effect": "review",
                    "match": {
                        "business": {
                            "schema": "guard.business-policy-match.v1",
                            "version": 1,
                            "services": ["google_gmail"],
                            "operations": ["mail_send"],
                        }
                    },
                    "lifetime": {"mode": "until", "expiresAt": "2026-07-16T12:00:00.123456789Z"},
                    "provenance": {"source": "local", "createdAt": "2026-07-15T00:00:00Z"},
                }
            ],
        },
    }
    if scoped:
        value["spec"]["rules"][0]["match"]["actors"] = ["private-fixture-marker"]
    return parse_policy_document_yaml(json.dumps(value))


def test_real_compiler_retains_complete_source_identity_and_exact_expiry(native_hook_force: Path) -> None:
    first = compile_business_policy_document(document())
    second = compile_business_policy_document(document(2))
    assert first.source_bytes == canonical_policy_document_bytes(document())
    assert first.source_digest == policy_document_digest(document())
    assert first.source_digest != second.source_digest
    assert first.binding()["sourceDocumentDigest"] == first.source_digest
    assert first.binding()["rules"][0]["expiresAt"] == "2026-07-16T12:00:00.123456789Z"
    edited = first.binding()
    edited["rules"].clear()
    assert len(first.binding()["rules"]) == 1
    assert not hasattr(first, "approval") and not hasattr(first, "installed")


def test_native_refuses_unrepresented_scope_without_source_in_diagnostic(native_hook_force: Path) -> None:
    with pytest.raises(NativePolicySnapshotError, match="native_business_document_compile_refused") as failure:
        compile_business_policy_document(document(scoped=True))
    assert "private-fixture-marker" not in str(failure.value)


def test_old_consumer_never_receives_source(monkeypatch: pytest.MonkeyPatch) -> None:
    old = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=("native-policy-snapshot-build-v1",)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: old)
    monkeypatch.setattr(
        native_runtime, "_run_native_process", lambda *args, **kwargs: pytest.fail("source crossed old boundary")
    )
    with pytest.raises(NativePolicySnapshotError, match="native_business_document_consumer_unavailable"):
        compile_business_policy_document(document())


def test_expired_deadline_never_selects_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: pytest.fail("expired discovery"))
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_deadline_exceeded"):
        compile_business_policy_document(document(), deadline_monotonic=time.monotonic() - 1)


def test_late_native_result_cannot_escape_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_business_document_compile as adapter

    ticks = iter([0.0, 0.0, 0.0, 6.0])
    monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=(COMPILE_CAPABILITY,)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(native_runtime, "_run_native_process", lambda *args, **kwargs: "late result")
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_deadline_exceeded"):
        compile_business_policy_document(document())


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_digest", "f" * 64),
        ("source_id", "policy.other"),
        ("source_revision", True),
        ("authority", "approved"),
        ("installed", True),
    ],
)
def test_compiler_response_cannot_substitute_source_or_claim_authority(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    source = document()
    digest = policy_document_digest(source)
    response = {
        "schema": "guard.business-policy-document-compile.v1",
        "source_digest": digest,
        "source_id": source.metadata.id,
        "source_revision": source.metadata.revision,
        "business_policy": {"sourceDocumentDigest": digest},
        "authority": "unverified_source",
        "installed": False,
    }
    response[field] = value
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("unused")),
        capabilities=SimpleNamespace(features=(COMPILE_CAPABILITY,)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **kwargs: status)
    monkeypatch.setattr(native_runtime, "_run_native_process", lambda *args, **kwargs: json.dumps(response))
    with pytest.raises(NativePolicySnapshotError, match="native_business_document_compile_response_invalid"):
        compile_business_policy_document(source)
