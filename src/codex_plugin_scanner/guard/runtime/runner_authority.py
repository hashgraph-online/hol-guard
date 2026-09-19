"""Authority.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner
from .runner_dependencies import contextmanager


def _resolved_exact_request_overrides(evaluation: runner.Mapping[str, object]) -> dict[str, str]:
    """Extract trusted allow results bound to the exact queued context token."""

    wait_result = evaluation.get("approval_wait")
    if not isinstance(wait_result, runner.Mapping) or wait_result.get("resolved") is not True:
        return {}
    raw_items = wait_result.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return {}
    items = [item for item in raw_items if isinstance(item, runner.Mapping)]
    if len(items) != len(raw_items) or any(
        item.get("status") != "resolved" or item.get("resolution_action") != "allow" for item in items
    ):
        return {}
    overrides: dict[str, str] = {}
    for item in items:
        artifact_id = item.get("artifact_id")
        artifact_hash = item.get("artifact_hash")
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(artifact_hash, str)
            or runner.parse_approval_context_token(artifact_hash) is None
        ):
            return {}
        overrides[artifact_id] = artifact_hash
    return overrides


def _resolved_interactive_request_overrides(
    evaluation: runner.Mapping[str, object],
) -> tuple[dict[str, str], dict[str, str]]:
    """Extract exact allow intents returned by the trusted terminal resolver."""

    raw_items = evaluation.get("artifacts")
    if not isinstance(raw_items, list):
        return {}, {}
    overrides: dict[str, str] = {}
    labels: dict[str, str] = {}
    for item in raw_items:
        if not isinstance(item, runner.Mapping) or item.get("policy_action") != "allow":
            continue
        user_override = item.get("user_override")
        artifact_id = item.get("artifact_id")
        artifact_hash = item.get("approval_context_hash")
        if (
            not isinstance(user_override, str)
            or user_override not in runner._INTERACTIVE_ALLOW_OVERRIDE_LABELS
            or not isinstance(artifact_id, str)
            or not artifact_id
            or not isinstance(artifact_hash, str)
            or runner.parse_approval_context_token(artifact_hash) is None
        ):
            continue
        overrides[artifact_id] = artifact_hash
        labels[artifact_id] = user_override
    return overrides, labels


def _runtime_detector_authority(
    evaluation: runner.Mapping[str, object],
) -> tuple[runner.GuardAction | None, str | None]:
    composition = evaluation.get("runtime_detector_composition")
    if not isinstance(composition, runner.Mapping):
        return None, None
    action = composition.get("action")
    reason = composition.get("reason")
    if not runner.is_guard_action(action) or action not in {"allow", "warn", "review", "block"}:
        return None, None
    return action, reason if isinstance(reason, str) and reason else None


def _runtime_detector_context(evaluation: runner.Mapping[str, object]) -> dict[str, object] | None:
    """Return timing-free detector authority suitable for exact context hashing."""

    raw_composition = evaluation.get("runtime_detector_composition")
    composition = (
        {
            "action": raw_composition.get("action"),
            "reason": raw_composition.get("reason"),
            "downgraded": raw_composition.get("downgraded") is True,
            "upgraded": raw_composition.get("upgraded") is True,
        }
        if isinstance(raw_composition, runner.Mapping)
        else {}
    )
    raw_signals = evaluation.get("runtime_detector_signals_v2")
    signals = (
        [dict(signal) for signal in raw_signals if isinstance(signal, runner.Mapping)]
        if isinstance(raw_signals, list)
        else []
    )
    telemetry = runner._normalized_runtime_detector_telemetry(evaluation)
    if not composition and not signals and not telemetry:
        return None
    return {"composition": composition, "signals_v2": signals, "telemetry": telemetry}


def _normalized_runtime_detector_telemetry(evaluation: runner.Mapping[str, object]) -> list[dict[str, object]]:
    """Bind semantic detector outcomes while excluding nondeterministic duration."""

    raw_telemetry = evaluation.get("runtime_detector_telemetry")
    if not isinstance(raw_telemetry, list):
        return []
    telemetry: list[dict[str, object]] = []
    for raw_item in raw_telemetry:
        if not isinstance(raw_item, runner.Mapping):
            continue
        item = {str(key): value for key, value in raw_item.items() if isinstance(key, str) and key != "elapsed_ms"}
        categories = item.get("categories")
        if isinstance(categories, (list, tuple)):
            item["categories"] = sorted({category for category in categories if isinstance(category, str)})
        telemetry.append(item)
    return sorted(
        telemetry,
        key=lambda item: runner.json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
    )


def _runtime_detector_nonterminal_evidence(
    action: runner.GuardAction | None,
    reason: str | None,
) -> dict[str, object] | None:
    if action == "warn":
        return {
            "source": "runtime_detector_registry",
            "status": "warning",
            "reason_code": runner._RUNTIME_DETECTOR_WARN_REASON,
            "reason": reason or "runtime detector signals require a warning",
        }
    if action == "review":
        return {
            "source": "runtime_detector_registry",
            "status": "review-required",
            "reason_code": runner._RUNTIME_DETECTOR_REVIEW_REASON,
            "reason": reason or "runtime detector signals require review",
        }
    return None


def _config_with_current_authority(
    config: runner.GuardConfig,
    evaluation: runner.Mapping[str, object],
    authority_action: runner.GuardAction,
    *,
    artifact_ids: set[str] | None = None,
) -> runner.GuardConfig:
    """Bind runner-only authority into each artifact's current policy context.

    Runtime detector composition happens outside the consumer service.  A
    synthetic per-artifact override makes that current authority participate
    in approval-context hashing and saved-decision composition before any
    one-shot claim. Existing stronger current actions remain authoritative.
    """

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        return config
    artifact_actions = dict(config.artifact_actions or {})
    changed = False
    for item in raw_artifacts:
        if not isinstance(item, runner.Mapping):
            continue
        artifact_id = item.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id:
            continue
        if artifact_ids is not None and artifact_id not in artifact_ids:
            continue
        composition = item.get("policy_composition")
        current_action = composition.get("current_action") if isinstance(composition, runner.Mapping) else None
        if not runner.is_guard_action(current_action):
            current_action = item.get("policy_action")
        composed = runner.most_restrictive_guard_action(current_action, authority_action, unknown_action="block")
        if artifact_actions.get(artifact_id) != composed:
            artifact_actions[artifact_id] = composed
            changed = True
    return runner.replace(config, artifact_actions=artifact_actions) if changed else config


def _receipt_rowid_cursor(store: runner.GuardStore) -> int:
    with store._connect() as connection:
        row = connection.execute("select coalesce(max(rowid), 0) as cursor from runtime_receipts").fetchone()
    return int(row["cursor"]) if row is not None else 0


def _saved_decision_is_retained(decision: runner.Mapping[str, object]) -> bool:
    """Return whether a successful claim leaves the authority row in place."""

    approval_id = decision.get("approval_id")
    if isinstance(approval_id, str) and approval_id:
        artifact_id = decision.get("artifact_id")
        return isinstance(artifact_id, str) and ":package-request:" in artifact_id
    decision_id = decision.get("decision_id")
    if isinstance(decision_id, int) and not isinstance(decision_id, bool):
        return not (decision.get("source") == "approval-gate" and decision.get("expires_at") is not None)
    # The store rejects unknown claim identities. Classifying them as retained
    # is the conservative fallback if an alternate store implementation ever
    # accepts one: absence may not be treated as proof of consumption.
    return True


def _append_authority_evidence_to_receipts(
    store: runner.GuardStore,
    *,
    after_rowid: int,
    evaluation: runner.Mapping[str, object],
    evidence: runner.Mapping[str, object],
    approval_source: str,
    source_actions: frozenset[str],
    replace_existing_source: bool = False,
) -> None:
    """Attach runner-composed authority to receipts emitted by one evaluation."""

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return
    artifact_ids = {
        artifact_id
        for item in raw_artifacts
        if isinstance(item, runner.Mapping)
        for artifact_id in (item.get("artifact_id"),)
        if isinstance(artifact_id, str) and artifact_id
    }
    if not artifact_ids:
        return
    reason_code = evidence.get("reason_code")
    # Runtime detector authority is composed in this aggregate, so its receipt
    # evidence is amended in the same local transaction boundary.
    with store._connect() as connection:
        rows = connection.execute(
            """
            select rowid, artifact_id, policy_decision, scanner_evidence_json, approval_source
            from runtime_receipts
            where rowid > ?
            order by rowid asc
            """,
            (after_rowid,),
        ).fetchall()
        for row in rows:
            if str(row["artifact_id"]) not in artifact_ids:
                continue
            try:
                raw_evidence = runner.json.loads(str(row["scanner_evidence_json"]))
            except (TypeError, ValueError):
                raw_evidence = []
            scanner_evidence = list(raw_evidence) if isinstance(raw_evidence, list) else []
            if replace_existing_source:
                scanner_evidence = [
                    item
                    for item in scanner_evidence
                    if not isinstance(item, runner.Mapping) or item.get("source") != evidence.get("source")
                ]
            if not any(
                isinstance(item, runner.Mapping)
                and item.get("source") == evidence.get("source")
                and item.get("reason_code") == reason_code
                for item in scanner_evidence
            ):
                scanner_evidence.append(dict(evidence))
            current_source = row["approval_source"]
            next_source = approval_source if str(row["policy_decision"]) in source_actions else current_source
            connection.execute(
                """
                update runtime_receipts
                set scanner_evidence_json = ?, approval_source = ?
                where rowid = ?
                """,
                (runner.json.dumps(scanner_evidence, sort_keys=True), next_source, int(row["rowid"])),
            )


def _get_default_detector_registry() -> runner.DetectorRegistry:
    factory = runner.register_default_detectors
    cached = runner._DEFAULT_DETECTOR_REGISTRY
    if cached is not None and cached[0] is factory:
        return cached[1]
    with runner._DEFAULT_DETECTOR_REGISTRY_LOCK:
        cached = runner._DEFAULT_DETECTOR_REGISTRY
        if cached is None or cached[0] is not factory:
            cached = (factory, runner.DetectorRegistry(factory()))
            runner._DEFAULT_DETECTOR_REGISTRY = cached
    return cached[1]


@contextmanager
def _guard_sync_auth_lock(store: runner.GuardStore):
    with store.hold_oauth_refresh_lock():
        yield
