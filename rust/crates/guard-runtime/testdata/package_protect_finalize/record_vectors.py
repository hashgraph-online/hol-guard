#!/usr/bin/env python3
"""Record package-protect finalize vectors from the ORIGINAL Python tail.

The decision tail of ``local_supply_chain._final_package_protect_authority``
(everything after the authority rebuild) has since moved into the resident's
``package_protect_finalize`` op. Re-recording needs a checkout from before that
removal (the commit that added this file) and a native runtime for the
resident calls that tail made, never Rust output for the op under test:

    HOL_GUARD_NATIVE_BINARY=<hol-guard-runtime> HOL_GUARD_NATIVE=force \
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

The file is compact: shared ``bases`` (evaluations a reply patches) and
``hashes`` (approval context tokens) are hoisted and referenced by key, the
request ``evaluation`` is the base's decision subset, ``stored_policy`` is
rebuilt from the current artifact plus either the default facts or the facts of
the ``resolve_case`` in ``package_policy_resolve_vectors.json``, and
``result`` names the shared set of evaluation fields the original tail
changed (``results``).
:func:`_expand` is the reading the Rust replay test mirrors; recording asserts
it reproduces every full vector. Stored rows run unclaimed and
claimed-consumed; a retained claim only differs once the refreshed policy
reuses nothing, which the scripted ``claimed_retained_*`` cases cover.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import local_supply_chain as lsc
from codex_plugin_scanner.guard import native_package_policy_resolve as resolve_bridge
from codex_plugin_scanner.guard.native_context import bind_context_digest_home
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.runtime.package_request_evaluation import SupplyChainUserCopy

WORKSPACE = Path("/workspace/demo")
NOW = "2026-10-15T12:00:00Z"
RESOLVE_VECTORS = Path(__file__).resolve().parent.parent / "package_policy_resolve_vectors.json"
FACT_KEYS = (
    "decision",
    "ignored_integrity",
    "daemon_authority",
    "diagnosed_reason",
    "diagnosed_stored_hash",
    "bundle_rules",
    "approval_request",
)
DEFAULT_FACTS = {"ignored_integrity": False, "daemon_authority": False}
EVALUATION_KEYS = ("policy_action", "reasons", "packages")
VIEW_KEYS = ("decision", "policy_action", "reasons", "packages", "risk_summary", "record_monitor_evidence")


@dataclass(frozen=True, slots=True)
class _Evaluation:
    decision: str
    policy_action: str
    reasons: tuple[dict[str, object], ...]
    packages: tuple[dict[str, object], ...]
    risk_summary: str
    user_copy: SupplyChainUserCopy
    record_monitor_evidence: bool


def _token(**changes: str) -> str:
    fields = {
        key: f"{index + 1:x}" * 64
        for index, key in enumerate(("identity", "content", "capabilities", "policy", "sandbox"))
    }
    fields.update(changes)
    payload = json.dumps({**fields, "version": 1}, sort_keys=True, separators=(",", ":")).encode()
    return "guard-approval-context:v1:" + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


TOKEN = _token()


def _evaluation(
    policy_action: str, decision: str, code: str, *, summary: str = "Current package evaluation."
) -> _Evaluation:
    return _Evaluation(
        decision=decision,
        policy_action=policy_action,
        reasons=({"code": code, "message": summary},),
        packages=({"name": "guard-proof", "decision": decision},),
        risk_summary=summary,
        user_copy=SupplyChainUserCopy(
            title="Current package result",
            summary=summary,
            next_step=None,
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _from_view(view: dict[str, object]) -> _Evaluation:
    copy = view["user_copy"]
    assert isinstance(copy, dict)
    return _Evaluation(
        decision=str(view["decision"]),
        policy_action=str(view["policy_action"]),
        reasons=tuple(dict(item) for item in view["reasons"]),  # type: ignore[union-attr]
        packages=tuple(dict(item) for item in view["packages"]),  # type: ignore[union-attr]
        risk_summary=str(view["risk_summary"]),
        user_copy=SupplyChainUserCopy(**copy),
        record_monitor_evidence=bool(view["record_monitor_evidence"]),
    )


def _view(evaluation: object) -> dict[str, object]:
    view: dict[str, object] = {key: getattr(evaluation, key) for key in VIEW_KEYS}
    view["reasons"] = [dict(item) for item in view["reasons"]]  # type: ignore[union-attr]
    view["packages"] = [dict(item) for item in view["packages"]]  # type: ignore[union-attr]
    view["user_copy"] = evaluation.user_copy.to_dict()  # type: ignore[attr-defined]
    return json.loads(json.dumps(view))


REVIEW = _evaluation("review", "ask", "current_package_result")
ALLOW = _evaluation("allow", "allow", "current_package_result")
FAILED_CLAIM = _evaluation("review", "ask", "approval_reuse_claim_failed", summary="Saved approval claim failed.")
CLAIMED = _evaluation("allow", "allow", "saved_package_approval", summary="Saved approval claimed.")
BASES = {"review": REVIEW, "allow": ALLOW, "failed_claim": FAILED_CLAIM}


def _authority(
    *, evaluation: _Evaluation, current_action: str, artifact_id: str, artifact_hash: str, harness: str, observe: bool
) -> SimpleNamespace:
    return SimpleNamespace(
        artifact=SimpleNamespace(artifact_id=artifact_id, harness=harness, publisher=None),
        artifact_hash=artifact_hash,
        evaluation=evaluation,
        current_action=current_action,
        execution_context=SimpleNamespace(),
        observe_mode=observe,
        additional_current_action=None,
        additional_policy_context=None,
        invoking_harness="codex",
    )


def _case(
    name: str,
    *,
    evaluation: _Evaluation = REVIEW,
    current_action: str | None = "review",
    claim: str | None = None,
    disposition: str | None = None,
    observe: bool = False,
    initial_id: str = "command:npm-install",
    current_id: str = "command:npm-install",
    initial_hash: str = TOKEN,
    current_hash: str = TOKEN,
    harness: str = "codex",
    facts: dict[str, object] | None = None,
    resolve_case: str | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "resolve_case": resolve_case,
        "evaluation": evaluation,
        "current_action": current_action,
        "claim": claim,
        "disposition": disposition,
        "observe": observe,
        "initial_id": initial_id,
        "current_id": current_id,
        "initial_hash": initial_hash,
        "current_hash": current_hash,
        "harness": harness,
        "facts": facts if facts is not None else dict(DEFAULT_FACTS),
    }


def _scripted_cases() -> list[dict[str, object]]:
    legacy = "sha256:" + "ab" * 32
    changed = _token(content="f" * 64)
    cases = [
        _case("rebuild_found_no_intent", current_action=None),
        _case("rebuild_found_no_intent_after_claim", current_action=None, claim="ok", disposition="consumed"),
        _case("claim_failed_same_action", claim="failed"),
        _case("claim_failed_current_block", claim="failed", current_action="block"),
        _case("claim_failed_current_require_reapproval", claim="failed", current_action="require-reapproval"),
        _case("observe_same_action", observe=True),
        _case("observe_current_block", observe=True, current_action="block"),
        _case("observe_identity_changed", observe=True, current_id="command:npm-install-other"),
        _case("plain_unclaimed", facts=None),
        _case("plain_unclaimed_allow", evaluation=ALLOW, current_action="allow"),
        _case("plain_unclaimed_current_warn", current_action="warn"),
    ]
    for prefix, claim, disposition, saved in (
        ("claimed_consumed", "ok", "consumed", "allow"),
        ("claimed_retained", "ok", "retained", "allow"),
        ("claimed_no_disposition", "ok", None, "allow"),
        ("unclaimed", None, None, "require-reapproval"),
    ):
        del saved
        cases += [
            _case(f"{prefix}_identity_changed", claim=claim, disposition=disposition, current_id="command:npm-other"),
            _case(f"{prefix}_content_changed", claim=claim, disposition=disposition, current_hash=changed),
            _case(
                f"{prefix}_legacy_hash", claim=claim, disposition=disposition, initial_hash=legacy, current_hash=legacy
            ),
            _case(
                f"{prefix}_identity_changed_block",
                claim=claim,
                disposition=disposition,
                current_id="x",
                current_action="block",
            ),
        ]
        for action in ("review", "require-reapproval", "warn", "sandbox-required", "block"):
            cases.append(
                _case(f"{prefix}_nothing_saved_{action}", claim=claim, disposition=disposition, current_action=action)
            )
        cases.append(
            _case(
                f"{prefix}_nothing_saved_allow",
                claim=claim,
                disposition=disposition,
                evaluation=ALLOW,
                current_action="allow",
            )
        )
    return cases


def _resolve_fact_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for vector in json.loads(RESOLVE_VECTORS.read_text(encoding="utf-8")):
        request = vector["request"]
        facts = {key: request[key] for key in FACT_KEYS if key in request}
        base = _from_view(vector["base"])
        current_action = request.get("current_action")
        if not isinstance(current_action, str):
            current_action = base.policy_action
        for prefix, claim, disposition in (("unclaimed", None, None), ("claimed_consumed", "ok", "consumed")):
            cases.append(
                _case(
                    f"{prefix}_{vector['name']}",
                    evaluation=base,
                    current_action=current_action,
                    claim=claim,
                    disposition=disposition,
                    initial_id=request["artifact_id"],
                    current_id=request["artifact_id"],
                    initial_hash=request["artifact_hash"],
                    current_hash=request["artifact_hash"],
                    harness=request["harness"],
                    facts=facts,
                    resolve_case=vector["name"],
                )
            )
    return cases


def _request(case: dict[str, object], base: _Evaluation) -> dict[str, object]:
    """The op request the bridge sends for ``case`` (envelope fields omitted)."""

    rebuilt = case["current_action"] is not None
    claim_failed = case["claim"] == "failed"
    request: dict[str, object] = {
        "evaluation": {
            "policy_action": base.policy_action,
            "reasons": [dict(item) for item in base.reasons],
            "packages": [dict(item) for item in base.packages],
        },
        "initial_artifact_id": case["initial_id"],
        "initial_artifact_hash": case["initial_hash"],
        "observe_mode": bool(rebuilt and case["observe"]),
        "claim_failed": claim_failed,
        "saved_approval_claimed": case["claim"] == "ok",
    }
    if rebuilt:
        request["current_action"] = case["current_action"]
        request["current_artifact_id"] = case["current_id"]
        request["current_artifact_hash"] = case["current_hash"]
    if case["claim"] == "ok" and case["disposition"] is not None:
        request["claim_disposition"] = case["disposition"]
    if rebuilt and not claim_failed and not case["observe"] and case["current_id"] == case["initial_id"]:
        request["stored_policy"] = {
            "harness": case["harness"],
            "artifact_id": case["current_id"],
            "artifact_hash": case["current_hash"],
            "workspace_dir": str(WORKSPACE),
            **{key: value for key, value in case["facts"].items() if value is not None},  # type: ignore[union-attr]
        }
    return request


def _record(case: dict[str, object], store: SimpleNamespace) -> dict[str, object]:
    initial = _authority(
        evaluation=REVIEW,
        current_action="review",
        artifact_id=str(case["initial_id"]),
        artifact_hash=str(case["initial_hash"]),
        harness=str(case["harness"]),
        observe=False,
    )
    current = None
    if case["current_action"] is not None:
        current = _authority(
            evaluation=case["evaluation"],  # type: ignore[arg-type]
            current_action=str(case["current_action"]),
            artifact_id=str(case["current_id"]),
            artifact_hash=str(case["current_hash"]),
            harness=str(case["harness"]),
            observe=bool(case["observe"]),
        )
    original_resolve = lsc._resolve_stored_package_policy_override

    def scripted_resolve(evaluation: object, **kwargs: object) -> object:
        if kwargs.get("claim_saved_approval"):
            claimed = FAILED_CLAIM if case["claim"] == "failed" else CLAIMED
            return lsc._StoredPackagePolicyResolution(claimed, claim_disposition=case["disposition"])  # type: ignore[arg-type]
        return original_resolve(evaluation, **kwargs)  # type: ignore[arg-type]

    lsc._build_package_protect_authority = lambda **_kwargs: current  # type: ignore[assignment]
    lsc._resolve_stored_package_policy_override = scripted_resolve  # type: ignore[assignment]
    lsc._package_policy_workspace_candidates = lambda **_kwargs: (str(WORKSPACE),)  # type: ignore[assignment]
    resolve_bridge._hydrate = lambda _store, **_kwargs: {**case["facts"], "authority": None}  # type: ignore[assignment,dict-item]
    try:
        authority, result = lsc._final_package_protect_authority(
            initial=initial,  # type: ignore[arg-type]
            initial_saved_evaluation=CLAIMED,
            saved_approval_pending=case["claim"] is not None,
            command=["npm", "install", "guard-proof"],
            store=store,
            workspace_dir=WORKSPACE,
            now=NOW,
            config=None,
            current_config_provider=None,
            additional_authority_provider=None,
        )
    finally:
        lsc._resolve_stored_package_policy_override = original_resolve  # type: ignore[assignment]
    if current is None:
        base = initial.evaluation
        assert authority is initial
    else:
        base = FAILED_CLAIM if case["claim"] == "failed" else current.evaluation
        assert authority is current
    return {
        "name": case["name"],
        "resolve_case": case["resolve_case"],
        "base_key": _base_key(base),
        "request": _request(case, base),
        "base": _view(base),
        "expected": _view(result),
    }


def _base_key(base: _Evaluation) -> str | None:
    for key, shared in BASES.items():
        if base is shared:
            return key
    return None


def _expand(vector: dict[str, object], fixtures: dict[str, object], resolve: dict[str, dict]) -> dict[str, object]:
    """The full vector a compact one stands for (mirrored by the Rust test)."""

    case = resolve.get(str(vector.get("resolve_case")))
    base = case["base"] if case is not None else fixtures["bases"][vector["base"]]  # type: ignore[index]
    request = dict(vector["request"])  # type: ignore[arg-type]
    for key in ("initial_artifact_hash", "current_artifact_hash"):
        if key in request:
            request[key] = fixtures["hashes"][request[key]]  # type: ignore[index]
    request["evaluation"] = {key: base[key] for key in EVALUATION_KEYS}
    if vector["stored_policy"]:
        facts = DEFAULT_FACTS
        if case is not None:
            facts = {key: case["request"][key] for key in FACT_KEYS if case["request"].get(key) is not None}
        request["stored_policy"] = {
            "harness": case["request"]["harness"] if case is not None else "codex",
            "artifact_id": request["current_artifact_id"],
            "artifact_hash": request["current_artifact_hash"],
            "workspace_dir": str(WORKSPACE),
            **facts,
        }
    changes = fixtures["results"][vector["result"]]  # type: ignore[index]
    return {"name": vector["name"], "request": request, "base": base, "expected": {**base, **changes}}  # type: ignore[dict-item]


def _shared(table: dict[str, str], value: str, prefix: str) -> str:
    return table.setdefault(value, f"{prefix}{len(table)}")


def _compact(full: dict[str, object], hashes: dict[str, str], results: dict[str, str]) -> dict[str, object]:
    request = dict(full["request"])  # type: ignore[arg-type]
    del request["evaluation"]
    stored = request.pop("stored_policy", None) is not None
    for key in ("initial_artifact_hash", "current_artifact_hash"):
        if key in request:
            request[key] = _shared(hashes, request[key], "h")
    base, expected = full["base"], full["expected"]
    changes = {key: value for key, value in expected.items() if base.get(key) != value}  # type: ignore[union-attr]
    vector: dict[str, object] = {
        "name": full["name"],
        "request": request,
        "stored_policy": stored,
        "result": _shared(results, json.dumps(changes, sort_keys=True), "r"),
    }
    if full["resolve_case"] is not None:
        vector["resolve_case"] = full["resolve_case"]
    else:
        vector["base"] = full["base_key"]
    return vector


def main() -> None:
    output = Path(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="pkg-finalize-") as home:
        provision_native_policy_verifier_key(Path(home), bytes(range(32)))
        bind_context_digest_home(Path(home))
        store = SimpleNamespace(guard_home=Path(home))
        full = [_record(case, store) for case in (*_scripted_cases(), *_resolve_fact_cases())]
    names = [vector["name"] for vector in full]
    assert len(names) == len(set(names)), "vector names must be unique"
    hashes: dict[str, str] = {}
    results: dict[str, str] = {}
    vectors = [_compact(vector, hashes, results) for vector in full]
    fixtures = {
        "bases": {key: _view(base) for key, base in BASES.items()},
        "hashes": {key: value for value, key in hashes.items()},
        "results": {key: json.loads(value) for value, key in results.items()},
    }
    resolve = {item["name"]: item for item in json.loads(RESOLVE_VECTORS.read_text(encoding="utf-8"))}
    for compact, vector in zip(vectors, full, strict=True):
        if vector["base_key"] is None:
            assert vector["base"] == resolve[str(vector["resolve_case"])]["base"], vector["name"]
        expanded = _expand(compact, fixtures, resolve)
        assert expanded == {key: vector[key] for key in ("name", "request", "base", "expected")}, vector["name"]
    document = {**fixtures, "vectors": vectors}
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(vectors)} vectors")


if __name__ == "__main__":
    main()
