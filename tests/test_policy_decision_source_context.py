from codex_plugin_scanner.guard.models import GuardApprovalRequest, GuardReceipt, PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore, _runtime_scoped_exact_match_key


def _store(tmp_path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def test_list_policy_decisions_enriches_source_receipt_and_command(tmp_path) -> None:
    store = _store(tmp_path)
    receipt = GuardReceipt(
        receipt_id="receipt-policy-ux-1",
        timestamp="2026-06-14T12:00:00+00:00",
        harness="codex",
        artifact_id="codex:project:package-request:abc123",
        artifact_hash="2dd8986742cb4f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
        policy_decision="allow",
        capabilities_summary="Package install via pnpm",
        changed_capabilities=("package-request",),
        provenance_summary="hook event for package install",
        artifact_name="pnpm install",
        source_scope="~/projects/hol-points-portal",
    )
    store.add_receipt(receipt)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="allow",
            artifact_id="codex:project:package-request:abc123",
            artifact_hash="sha256:2dd8986742cb4f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
            workspace="workspace:testhash",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    items = store.list_policy_decisions()
    assert len(items) == 1
    item = items[0]
    assert isinstance(item["decision_id"], int)
    assert item["source_receipt_id"] == "receipt-policy-ux-1"
    assert item["remembered_command"] == "pnpm install"
    assert item["remembered_context"] == "Package install via pnpm"
    assert item["workspace_label"] == "hol-points-portal"


def test_list_policy_decisions_falls_back_to_inventory_launch_command(tmp_path) -> None:
    store = _store(tmp_path)
    with store._connect() as connection:
        connection.execute(
            """
            insert into artifact_inventory (
              artifact_id, harness, artifact_name, artifact_type, source_scope, config_path,
              first_seen_at, last_seen_at, last_policy_action, artifact_hash
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex:project:package-request:inv1",
                "codex",
                "pnpm",
                "package_request",
                "~/projects/hol-guard",
                "config.json",
                "2026-06-14T12:00:00+00:00",
                "2026-06-14T12:00:00+00:00",
                "allow",
                "hash-inv1",
            ),
        )
        connection.execute(
            "update artifact_inventory set launch_command = ? where artifact_id = ? and harness = ?",
            ("pnpm install --frozen-lockfile", "codex:project:package-request:inv1", "codex"),
        )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="allow",
            artifact_id="codex:project:package-request:inv1",
            artifact_hash="hash-inv1",
            workspace="workspace:inv",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions()[0]
    assert item["remembered_command"] == "pnpm install --frozen-lockfile"
    assert item["workspace_label"] == "hol-guard"


def test_list_policy_decisions_prefers_scanner_redacted_command(tmp_path) -> None:
    store = _store(tmp_path)
    scanner_payload = [
        {
            "package": {
                "redactedCommand": "pip install --force-reinstall hol-guard==2.0.345",
                "packageManager": "pip",
            }
        }
    ]
    receipt = GuardReceipt(
        receipt_id="receipt-scanner-cmd-1",
        timestamp="2026-06-14T12:00:00+00:00",
        harness="cursor",
        artifact_id="cursor:project:package-request:scanner123",
        artifact_hash="scannerhash1234567890abcdef1234567890abcdef1234567890abcdef12",
        policy_decision="allow",
        capabilities_summary="Package install",
        changed_capabilities=("package-request",),
        provenance_summary="runtime tool request evaluated from /srv/projects/sample-guard/mcp.json",
        artifact_name="npx execute tsx",
        source_scope="/srv/projects/sample-guard",
        scanner_evidence=tuple(scanner_payload),
    )
    store.add_receipt(receipt)
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id="cursor:project:package-request:scanner123",
            artifact_hash="scannerhash1234567890abcdef1234567890abcdef1234567890abcdef12",
            workspace="/srv/projects/sample-guard",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions()[0]
    assert item["source_receipt_id"] == "receipt-scanner-cmd-1"
    assert item["remembered_command"] == "pip install --force-reinstall hol-guard==2.0.345"
    assert item["remembered_context"] == "Package install via pip"
    assert item["source_scope_path"] == "/srv/projects/sample-guard"
    assert item["workspace_label"] == "sample-guard"


def test_list_policy_decisions_uses_trigger_summary_backticks(tmp_path) -> None:
    store = _store(tmp_path)
    request = GuardApprovalRequest(
        request_id="approval-trigger-1",
        harness="cursor",
        artifact_id="cursor:project:tool-action:tool123",
        artifact_name="bash",
        artifact_hash="toolhash1234567890abcdef1234567890abcdef1234567890abcdef1234",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="/srv/projects/sample-broker",
        config_path="/srv/projects/sample-broker/.cursor/mcp.json",
        workspace="/srv/projects/sample-broker",
        launch_target="git push origin main",
        trigger_summary="Allow shell command `git push origin main` from Cursor?",
        launch_summary="Shell command review",
        review_command="hol-guard approvals approve approval-trigger-1",
        approval_url="http://127.0.0.1:5481/approvals/approval-trigger-1",
    )
    store.add_approval_request(request, "2026-06-14T11:59:00+00:00")
    store.resolve_approval_request(
        "approval-trigger-1",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="approved in review",
        resolved_at="2026-06-14T12:00:00+00:00",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="cursor",
            scope="artifact",
            action="allow",
            artifact_id="cursor:project:tool-action:tool123",
            artifact_hash="toolhash1234567890abcdef1234567890abcdef1234567890abcdef1234",
            workspace="/srv/projects/sample-broker",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions()[0]
    assert item["remembered_command"] == "git push origin main"
    assert item["source_scope_path"] == "/srv/projects/sample-broker"
    assert item["workspace_label"] == "sample-broker"


def test_list_policy_decisions_batch_index_matches_single_lookup(tmp_path) -> None:
    store = _store(tmp_path)
    for index in range(3):
        receipt = GuardReceipt(
            receipt_id=f"receipt-batch-{index}",
            timestamp=f"2026-06-14T12:00:{index:02d}+00:00",
            harness="codex",
            artifact_id=f"codex:project:package-request:batch{index}",
            artifact_hash=f"batchhash{index:02d}abcdef1234567890abcdef1234567890abcdef12",
            policy_decision="allow",
            capabilities_summary=f"Package install via pnpm-{index}",
            changed_capabilities=("package-request",),
            provenance_summary="hook event for package install",
            artifact_name=f"pnpm install {index}",
            source_scope=f"/srv/projects/sample-{index}",
        )
        store.add_receipt(receipt)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="workspace",
                action="allow",
                artifact_id=f"codex:project:package-request:batch{index}",
                artifact_hash=f"batchhash{index:02d}abcdef1234567890abcdef1234567890abcdef12",
                workspace=f"workspace:batch{index}",
                reason="approved in review",
                source="local",
            ),
            f"2026-06-14T12:01:{index:02d}+00:00",
        )

    items = store.list_policy_decisions()
    assert len(items) == 3
    for item in items:
        assert item["source_receipt_id"] is not None
        assert item["remembered_command"] is not None


def test_list_policy_decisions_scales_without_per_row_queries(tmp_path) -> None:
    store = _store(tmp_path)
    for index in range(120):
        receipt = GuardReceipt(
            receipt_id=f"receipt-perf-{index}",
            timestamp=f"2026-06-14T12:00:{index % 60:02d}+00:00",
            harness="codex",
            artifact_id=f"codex:project:package-request:perf{index}",
            artifact_hash=f"perfhash{index:03d}abcdef1234567890abcdef1234567890abcdef12",
            policy_decision="allow",
            capabilities_summary="Package install via pnpm",
            changed_capabilities=("package-request",),
            provenance_summary="hook event for package install",
            artifact_name=f"pnpm install {index}",
            source_scope="/srv/projects/sample-guard",
        )
        store.add_receipt(receipt)
        store.upsert_policy(
            PolicyDecision(
                harness="codex",
                scope="workspace",
                action="allow",
                artifact_id=f"codex:project:package-request:perf{index}",
                artifact_hash=f"perfhash{index:03d}abcdef1234567890abcdef1234567890abcdef12",
                workspace=f"workspace:perf{index}",
                reason="approved in review",
                source="local",
            ),
            f"2026-06-14T12:01:{index % 60:02d}+00:00",
        )

    items = store.list_policy_decisions()
    assert len(items) == 120
    assert all(item["remembered_command"] is not None for item in items)


def test_list_policy_decisions_supports_global_harness_scope(tmp_path) -> None:
    store = _store(tmp_path)
    receipt = GuardReceipt(
        receipt_id="receipt-global-1",
        timestamp="2026-06-14T12:00:00+00:00",
        harness="codex",
        artifact_id="codex:project:package-request:global1",
        artifact_hash="globalhash1234567890abcdef1234567890abcdef1234567890ab",
        policy_decision="allow",
        capabilities_summary="Package install via pnpm",
        changed_capabilities=("package-request",),
        provenance_summary="hook event for package install",
        artifact_name="pnpm install",
        source_scope="/srv/projects/sample-guard",
    )
    store.add_receipt(receipt)
    store.upsert_policy(
        PolicyDecision(
            harness="*",
            scope="artifact",
            action="allow",
            artifact_id="codex:project:package-request:global1",
            artifact_hash="globalhash1234567890abcdef1234567890abcdef1234567890ab",
            workspace="workspace:global",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions()[0]
    assert item["source_receipt_id"] == "receipt-global-1"
    assert item["remembered_command"] == "pnpm install"


def test_list_policy_decisions_enriches_harness_exact_match_policy_from_receipt(tmp_path) -> None:
    store = _store(tmp_path)
    artifact_id = "opencode:project:package-request:exact1"
    receipt = GuardReceipt(
        receipt_id="receipt-exact-1",
        timestamp="2026-06-14T12:00:00+00:00",
        harness="opencode",
        artifact_id=artifact_id,
        artifact_hash="88a55337a11b7c7f6f4f2f3b9f7c4d1a88a55337a11b7c7f6f4f2f3b9f7c4d1a",
        policy_decision="allow",
        capabilities_summary="Package install via pnpm",
        changed_capabilities=("package-request",),
        provenance_summary="hook event for package install",
        artifact_name="pnpm install lodash",
        source_scope="/srv/projects/hol-guard",
    )
    store.add_receipt(receipt)
    store.upsert_policy(
        PolicyDecision(
            harness="opencode",
            scope="harness",
            action="allow",
            artifact_id=artifact_id,
            artifact_hash=_runtime_scoped_exact_match_key(artifact_id),
            workspace=None,
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )

    item = store.list_policy_decisions(harness="opencode")[0]
    assert item["artifact_id"] == "family:package-request"
    assert item["source_receipt_id"] == "receipt-exact-1"
    assert item["remembered_command"] == "pnpm install lodash"
    assert item["remembered_context"] == "Package install via pnpm"
    assert item["workspace_label"] == "hol-guard"

    with store._connect() as connection:
        row = connection.execute("select * from policy_decisions").fetchone()
        assert row is not None
        direct_item = GuardStore._policy_decision_dict_from_row(connection, row)
    assert direct_item["source_receipt_id"] == "receipt-exact-1"
    assert direct_item["remembered_command"] == "pnpm install lodash"


def test_list_policy_decisions_keeps_inventory_context_with_global_policy(tmp_path) -> None:
    store = _store(tmp_path)
    with store._connect() as connection:
        connection.execute(
            """
            insert into artifact_inventory (
              artifact_id, harness, artifact_name, artifact_type, source_scope, config_path,
              first_seen_at, last_seen_at, last_policy_action, artifact_hash
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex:project:package-request:mixed1",
                "codex",
                "pnpm",
                "package_request",
                "/srv/projects/sample-guard",
                "config.json",
                "2026-06-14T12:00:00+00:00",
                "2026-06-14T12:00:00+00:00",
                "allow",
                "hash-mixed1",
            ),
        )
        connection.execute(
            "update artifact_inventory set launch_command = ? where artifact_id = ? and harness = ?",
            ("pnpm install --frozen-lockfile", "codex:project:package-request:mixed1", "codex"),
        )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="workspace",
            action="allow",
            artifact_id="codex:project:package-request:mixed1",
            artifact_hash="hash-mixed1",
            workspace="workspace:mixed",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:01:00+00:00",
    )
    store.upsert_policy(
        PolicyDecision(
            harness="*",
            scope="artifact",
            action="allow",
            artifact_id="codex:project:package-request:global-mixed",
            artifact_hash="globalmixedhash1234567890abcdef1234567890abcdef12",
            workspace="workspace:global",
            reason="approved in review",
            source="local",
        ),
        "2026-06-14T12:02:00+00:00",
    )

    items = {str(item["artifact_id"]): item for item in store.list_policy_decisions()}
    assert items["codex:project:package-request:mixed1"]["remembered_command"] == "pnpm install --frozen-lockfile"
