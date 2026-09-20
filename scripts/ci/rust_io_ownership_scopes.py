"""Exact path scopes for the decision-critical I/O ownership inventory."""

from __future__ import annotations

from typing import Final

_COMPATIBILITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/runtime/hook_source_read.py",
        "src/codex_plugin_scanner/guard/runtime/hook_content_scanner.py",
        "src/codex_plugin_scanner/guard/runtime/hook_decision_cache.py",
        "src/codex_plugin_scanner/guard/runtime/hook_review_engine.py",
        "src/codex_plugin_scanner/guard/runtime/source_paths.py",
        "src/codex_plugin_scanner/guard/native_command_model.py",
    }
)
_TRANSPORT_IDENTITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_runtime.py",
        "src/codex_plugin_scanner/guard/native_runtime_identity.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime_resident.py",
        "src/codex_plugin_scanner/guard/native_runtime_resilience.py",
        "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
    }
)
_TRANSPORT_DECODE_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/native_pretool.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        # Bounded in-memory PostTool output extraction for recording evidence.
        "src/codex_plugin_scanner/guard/runtime/hook_output_text.py",
    }
)
_ASYNC_POLICY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/mdm/policy.py",
        "src/codex_plugin_scanner/guard/mdm/managed_file_trust.py",
        "src/codex_plugin_scanner/guard/mdm/contracts.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_context.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_resident_inputs.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_storage.py",
        "src/codex_plugin_scanner/guard/config.py",
        "src/codex_plugin_scanner/guard/runtime/command_activity_correlation.py",
    }
)
_PERSISTENCE_PATH_PREFIXES: Final = (
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
    "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/local_dashboard_session.py",
)
