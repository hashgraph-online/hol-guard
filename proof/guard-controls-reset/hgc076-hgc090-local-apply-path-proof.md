# HGC076-HGC090 Local Policy Apply Path Proof

Primary evidence:
- `src/codex_plugin_scanner/guard/runtime/runner.py`
- `src/codex_plugin_scanner/guard/daemon/server.py`
- `tests/test_policy_bundle_parser.py`
- `tests/test_guard_runtime.py`
- `tests/test_guard_headless_daemon_api.py`
- `tests/test_guard_local_supply_chain_phase15.py`

Verification:
- `python3 -m pytest tests/test_policy_bundle_parser.py::test_hgc076_policy_bundle_acknowledgement_payload -q`
- `python3 -m pytest tests/test_guard_headless_daemon_api.py::test_headless_policy_sync_accepts_policy_bundle_and_returns_bundle_metadata tests/test_guard_headless_daemon_api.py::test_headless_policy_sync_rejects_unsupported_daemon_version -q`
- `python3 -m pytest tests/test_guard_runtime.py::test_sync_receipts_uploads_policy_bundle_acknowledgement_to_sync_route tests/test_guard_runtime.py::test_sync_receipts_preserves_last_known_good_policy_bundle_on_invalid_update tests/test_guard_runtime.py::test_policy_bundle_decisions_map_to_runtime_families tests/test_guard_runtime.py::test_policy_bundle_decision_resolves_before_receipt_persistence tests/test_guard_runtime.py::test_simulate_policy_bundle_receipts_replays_recent_receipts_without_enforcing tests/test_guard_runtime.py::test_simulate_policy_bundle_receipts_reports_event_freshness -q`
- `python3 -m pytest tests/test_guard_local_supply_chain_phase15.py::test_guard_protect_receipt_keeps_matched_policy_rule_metadata tests/test_guard_local_supply_chain_phase15.py::test_guard_protect_routes_package_requests_through_supply_chain_eval_and_redacts_command -q`

Covered outcomes:
- Acknowledgement payload includes device id, bundle version/hash, status, and appliedAt.
- `/v1/policy/sync` applies cloud bundles and returns version/hash metadata.
- Receipt sync applies bundles without corrupting last-known-good policy on invalid updates.
- Bundle rules map to runtime families for package, MCP, file-read, and shell/tool actions.
- Policy resolves before receipt persistence; simulation replays recent receipts without enforcing.
