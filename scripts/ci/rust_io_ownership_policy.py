"""Reviewed I/O categories and path classifications for the ownership gate."""

from typing import Final

SCHEMA: Final = "hol-guard.decision-critical-io.v1"
NATIVE_MODES: Final = frozenset({"auto", "force"})
COMPATIBILITY_MODES: Final = frozenset({"off", "shadow"})

_FS_METHODS: Final = frozenset(
    {
        "open",
        "read",
        "read_bytes",
        "read_text",
        "stat",
        "lstat",
        "readlink",
        "iterdir",
        "glob",
        "rglob",
        "resolve",
        "exists",
        "is_file",
        "is_dir",
        "is_symlink",
        "realpath",
    }
)
_FS_FUNCTIONS: Final = frozenset({"open", "readlink", "stat", "lstat", "listdir", "scandir"})
_HASH_FUNCTIONS: Final = frozenset({"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"})
_ARCHIVE_MODULES: Final = frozenset({"tarfile", "zipfile", "gzip", "bz2", "lzma", "shutil"})
_DECODE_FUNCTIONS: Final = frozenset({"b64decode", "loads", "decode", "unpack", "decompress"})
# This codec only encodes request bytes; the resident owns decompression,
# command parsing, normalization and identity derivation.
_TRANSPORT_ENCODE_OPERATIONS: Final = frozenset(
    {("src/codex_plugin_scanner/guard/native_rich_command_model.py", ("gzip", "compress"))}
)
_EQUIVALENCE_FUNCTIONS: Final = frozenset({"output_equivalent", "parity_signature", "sha256_text"})

_COMPATIBILITY_PATHS: Final = frozenset({"src/codex_plugin_scanner/guard/native_command_model.py"})
_TRANSPORT_IDENTITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_shell_request_authority.py",
        "src/codex_plugin_scanner/guard/native_developer_inspection_authority.py",
        "src/codex_plugin_scanner/guard/native_restricted_pytest.py",
        # Resolves the session directory a launch is bound to; the native
        # runtime decides what the program found from it may reach.
        "src/codex_plugin_scanner/guard/daemon/hook_native_exact_action.py",
        # Payload-reference metadata validation; the native edge reads bytes.
        "src/codex_plugin_scanner/guard/daemon/hook_request_parsing.py",
        # Archive-inspection transport: lease, request binding, and the
        # bounded native worker invocation; all archive semantics are Rust.
        "src/codex_plugin_scanner/guard/native_archive_inspection.py",
        # Native acquisition request binding and managed trust DTO transport.
        "src/codex_plugin_scanner/guard/native_archive_acquisition.py",
        # Request identity and typed portable-policy DTO transport only.
        "src/codex_plugin_scanner/guard/native_policy_document.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        # Per-request status reuse. stat() only rechecks the validated binary.
        "src/codex_plugin_scanner/guard/native_runtime_request_scope.py",
        # Process-wide verified status reuse; stat() fingerprints gate every hit.
        "src/codex_plugin_scanner/guard/native_runtime_process_cache.py",
        # Extracted binary identity validation; no command or policy semantics.
        "src/codex_plugin_scanner/guard/native_binary_identity.py",
        # Windows read handle that locks writers out of the validated binary.
        "src/codex_plugin_scanner/guard/native_binary_write_lock.py",
        "src/codex_plugin_scanner/guard/native_context.py",
        "src/codex_plugin_scanner/guard/native_content_sensitivity.py",
        # Bounded non-secret reason code for resident prerequisite failures.
        "src/codex_plugin_scanner/guard/native_resident_prerequisite_reason.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime_resilience.py",
        "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
        "src/codex_plugin_scanner/guard/daemon/manager.py",
        "src/codex_plugin_scanner/guard/daemon/manager_ephemeral_reap.py",
        "src/codex_plugin_scanner/guard/daemon/manager_process_query.py",
        # Interpreter bootstrap identity only; no policy or command decisions.
        "src/codex_plugin_scanner/guard/daemon/pipx_import_paths.py",
        # Resident request transport; the observed git path is a fact, never a verdict.
        "src/codex_plugin_scanner/guard/native_codex_tool_output.py",
        # Resident sensitive-request transport; the observed git path is a fact, never a verdict.
        "src/codex_plugin_scanner/guard/native_sensitive_request.py",
        "src/codex_plugin_scanner/guard/frozen_runtime_commands.py",
    }
)
_TRANSPORT_INTEGRITY_PATHS: Final = frozenset(
    {
        # Reassembled resident fragments are bound by the native result digest.
        "src/codex_plugin_scanner/guard/native_shell_helpers.py",
        "src/codex_plugin_scanner/guard/native_decision_receipt.py",
        "src/codex_plugin_scanner/guard/native_rich_command_model.py",
        "src/codex_plugin_scanner/guard/native_command_observations.py",
        "src/codex_plugin_scanner/guard/native_context.py",
        # Execution-environment digest binds transport context without carrying
        # the environment values themselves.
        "src/codex_plugin_scanner/guard/hook_execution_environment.py",
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/daemon/hook_native_review_approval.py",
        # The request digest correlates resident framing; it never owns a
        # semantic approval, policy, or context identity or decision.
        "src/codex_plugin_scanner/guard/native_approval_reuse.py",
        "src/codex_plugin_scanner/guard/native_archive_acquisition.py",
        # Same correlation-only digest for the approval-proof resident op.
        "src/codex_plugin_scanner/guard/native_approval_proof.py",
        # Same correlation-only digest for the store-policy claim and diagnostic ops.
        "src/codex_plugin_scanner/guard/native_store_policy.py",
        # Same correlation-only digest for the generic-hook decision resident op.
        "src/codex_plugin_scanner/guard/native_hook_decision.py",
        # Same correlation-only digest for the daemon route/auth policy op.
        "src/codex_plugin_scanner/guard/native_daemon_route.py",
        "src/codex_plugin_scanner/guard/native_daemon_handler.py",
        # Shared request lifecycle for the hook and route resident ops; digest
        # correlation only.
        "src/codex_plugin_scanner/guard/native_resident_decision.py",
        # Same correlation-only digest for the hook artifact composition op.
        "src/codex_plugin_scanner/guard/native_hook_artifact_compose.py",
        # Same correlation-only digest for the consumer artifact composition op.
        "src/codex_plugin_scanner/guard/native_consumer_artifact_compose.py",
        "src/codex_plugin_scanner/guard/native_consumer_artifact_project.py",
        # Same correlation-only digest for the per-harness hook adapter op.
        "src/codex_plugin_scanner/guard/native_hook_adapter.py",
        "src/codex_plugin_scanner/guard/native_hook_adapter_wire.py",
        "src/codex_plugin_scanner/guard/native_github_cli.py",
        # Same correlation-only digest for the Composio routing op.
        "src/codex_plugin_scanner/guard/native_composio_role.py",
        "src/codex_plugin_scanner/guard/native_shell_request_authority.py",
        # Same correlation-only digest for the GitHub workflow prepare op.
        "src/codex_plugin_scanner/guard/native_github_workflow.py",
        "src/codex_plugin_scanner/guard/native_protect_request.py",
        # Same correlation-only digest for the MCP tool-policy resident op.
        "src/codex_plugin_scanner/guard/native_mcp_tool_policy.py",
        "src/codex_plugin_scanner/guard/native_git_execution_safety.py",
        "src/codex_plugin_scanner/guard/native_policy_bundle.py",
        # Gathers ambient facts for and decodes the resident package-shim admin envelope; results stay Rust.
        "src/codex_plugin_scanner/guard/native_shim_admin.py",
        # Decodes the bounded resident MCP proxy decision envelope; verdicts stay Rust.
        "src/codex_plugin_scanner/guard/native_mcp_proxy_decision.py",
        # Decodes the bounded resident daemon-lifecycle verdict; decisions stay Rust.
        "src/codex_plugin_scanner/guard/native_daemon_lifecycle.py",
        # Gathers facts for and decodes the resident sensitive-read decisions; verdicts stay Rust.
        "src/codex_plugin_scanner/guard/native_mcp_sensitive_read.py",
        # Retry lineage is local diagnostic metadata. Its digests protect
        # reattachment integrity but never authorize or evaluate an action.
        "src/codex_plugin_scanner/guard/retry_lineage.py",
    }
)
_TRANSPORT_AUTHORITY_PATHS: Final = frozenset(
    {
        # Strict owner-checked native command-control lock and marker transport.
        "src/codex_plugin_scanner/guard/native_command_control_authority_io.py",
        # Locates the trusted Windows directory a contained-test request is
        # handed through; it reads no file content.
        "src/codex_plugin_scanner/guard/windows_paths.py",
    }
)
_TRANSPORT_DECODE_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_developer_inspection_authority.py",
        # Strict DTO decoding of request-bound rich parser replies; semantics are native.
        "src/codex_plugin_scanner/guard/native_rich_command_model.py",
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/native_pretool.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        # Resident-op dispatch bridge: decodes the bounded native response and
        # returns a DTO; it does not interpret response content into a decision.
        "src/codex_plugin_scanner/guard/native_execution.py",
        "src/codex_plugin_scanner/guard/native_shell_helpers.py",
        # Bounded response decoding for native package-authority results.
        "src/codex_plugin_scanner/guard/native_package_authority.py",
        # Bounded decoding of the resident artifact-risk reply (gzip-packed when
        # large); signals and summary are computed in Rust and only validated.
        "src/codex_plugin_scanner/guard/risk.py",
        # Bounded response decoding for the resident approval-identity/hash result.
        "src/codex_plugin_scanner/guard/native_package_approval_hash.py",
        "src/codex_plugin_scanner/guard/native_package_policy_resolve.py",
        "src/codex_plugin_scanner/guard/native_supply_chain_posture.py",
        "src/codex_plugin_scanner/guard/native_package_audit_projection.py",
        "src/codex_plugin_scanner/guard/native_package_protect_projection.py",
        "src/codex_plugin_scanner/guard/native_workspace_inventory.py",
        # Decodes the bounded resident command-effect result envelope and binds
        # it to the request; the decision itself is computed in Rust.
        "src/codex_plugin_scanner/guard/native_command_effect.py",
        # Bounded response decoding for resident package-verdict composition patches.
        "src/codex_plugin_scanner/guard/native_package_evaluation_compose.py",
        # Strict resident transport and DTO hydration for package supply-chain evaluation.
        "src/codex_plugin_scanner/guard/native_supply_chain_eval.py",
        # Decodes the bounded resident approval-reuse response envelope.
        "src/codex_plugin_scanner/guard/native_approval_reuse.py",
        # Decodes the bounded resident approval-proof response; the answer is
        # strictly validated and never reinterpreted into a decision.
        "src/codex_plugin_scanner/guard/native_approval_proof.py",
        # Decodes the bounded resident claim and diagnostic replies; the answer
        # is strictly bound to the request and never reinterpreted.
        "src/codex_plugin_scanner/guard/native_store_policy.py",
        # Decodes the bounded resident generic-hook decision response; the
        # answer is strictly validated and never reinterpreted into a decision.
        "src/codex_plugin_scanner/guard/native_hook_decision.py",
        # Decodes the bounded resident daemon route policy response; strictly
        # bound and validated, never reinterpreted.
        "src/codex_plugin_scanner/guard/native_daemon_route.py",
        "src/codex_plugin_scanner/guard/native_daemon_handler.py",
        # Shared strict reply validation for the hook and route resident ops;
        # the answer is bound and validated, never reinterpreted.
        "src/codex_plugin_scanner/guard/native_resident_decision.py",
        # Decodes the bounded resident hook artifact composition response; the
        # answer is strictly bound and validated, never reinterpreted.
        "src/codex_plugin_scanner/guard/native_hook_artifact_compose.py",
        # Decodes the bounded resident consumer artifact composition response;
        # the answer is strictly bound and validated, never reinterpreted.
        "src/codex_plugin_scanner/guard/native_consumer_artifact_compose.py",
        "src/codex_plugin_scanner/guard/native_consumer_artifact_project.py",
        # Decodes the bounded resident hook adapter response; the answer is
        # strictly bound and validated, never reinterpreted.
        "src/codex_plugin_scanner/guard/native_hook_adapter.py",
        "src/codex_plugin_scanner/guard/native_hook_adapter_wire.py",
        # Decodes the bounded resident GitHub CLI classification envelope.
        "src/codex_plugin_scanner/guard/native_github_cli.py",
        # Decodes the bounded resident Composio routing envelope; the role is
        # reported as the runtime named it and never re-derived.
        "src/codex_plugin_scanner/guard/native_composio_role.py",
        # Decodes the bounded resident GitHub workflow prepare envelope; the
        # record is strictly validated and never reinterpreted.
        "src/codex_plugin_scanner/guard/native_github_workflow.py",
        # Decodes the bounded resident install-time protect envelope.
        "src/codex_plugin_scanner/guard/native_protect_request.py",
        # Decodes the bounded resident MCP tool-policy envelope; the decision
        # DTO is strictly validated and never reinterpreted.
        "src/codex_plugin_scanner/guard/native_mcp_tool_policy.py",
        "src/codex_plugin_scanner/guard/native_git_execution_safety.py",
        "src/codex_plugin_scanner/guard/native_codex_tool_output.py",
        "src/codex_plugin_scanner/guard/native_policy_bundle.py",
        # Gathers ambient facts for and decodes the resident package-shim admin envelope; results stay Rust.
        "src/codex_plugin_scanner/guard/native_shim_admin.py",
        # Decodes the bounded resident MCP proxy decision envelope; verdicts stay Rust.
        "src/codex_plugin_scanner/guard/native_mcp_proxy_decision.py",
        # Decodes the bounded resident daemon-lifecycle verdict; decisions stay Rust.
        "src/codex_plugin_scanner/guard/native_daemon_lifecycle.py",
        # Gathers facts for and decodes the resident sensitive-read decisions; verdicts stay Rust.
        "src/codex_plugin_scanner/guard/native_mcp_sensitive_read.py",
        # Decodes the bounded resident MCP runtime-evidence response envelope.
        "src/codex_plugin_scanner/guard/native_mcp_runtime_evidence.py",
        # Decodes the bounded resident runtime-detector-run response envelope.
        "src/codex_plugin_scanner/guard/native_runtime_detectors.py",
        # Decodes the bounded resident runner-authority response envelope and
        # projects typed runner state to it; Rust owns every authority answer.
        "src/codex_plugin_scanner/guard/native_runner_authority.py",
        "src/codex_plugin_scanner/guard/native_continuation_authority.py",
        "src/codex_plugin_scanner/guard/native_decisions.py",
        "src/codex_plugin_scanner/guard/native_signal_projection.py",
        # Fused CLI input/identity DTO from the existing bound resident stream.
        "src/codex_plugin_scanner/guard/native_cli_runtime_support.py",
        "src/codex_plugin_scanner/guard/runtime/runner_native_authority.py",
        # Decodes the bounded resident MCP tool-evidence response envelope.
        "src/codex_plugin_scanner/guard/native_mcp_tool_evidence.py",
        # Normalizes the request to plain JSON types and decodes the bounded
        # resident tool-call identity envelope; identity and hashing stay Rust.
        "src/codex_plugin_scanner/guard/native_mcp_tool_call_identity.py",
        # JSON-safe DTO copy shared by the native runner-authority and MCP
        # tool-evidence projections; it carries no decision.
        "src/codex_plugin_scanner/guard/runtime/json_safe_copy.py",
        # Decodes the bounded resident attachment-scan reply into an
        # artifact; the scan, its bounds and its verdict are all Rust.
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_prompt_attachments.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        "src/codex_plugin_scanner/guard/native_context.py",
    }
)
_STRUCTURED_OUTPUT_MEDIATION_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/runtime/secret_sensitivity.py",
        "src/codex_plugin_scanner/guard/runtime/structured_data_sensitivity.py",
        "src/codex_plugin_scanner/guard/runtime/structured_output_mediation.py",
    }
)
_ASYNC_POLICY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/mdm/policy.py",
        "src/codex_plugin_scanner/guard/mdm/managed_file_trust.py",
        "src/codex_plugin_scanner/guard/mdm/contracts.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_inputs.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_storage.py",
        # Publisher-written, HMAC-bound per-harness posture sidecar for the
        # ACKed snapshot; read only to decide record-only versus enforce.
        "src/codex_plugin_scanner/guard/native_policy_snapshot_harness_postures.py",
        # Native-authenticated source binding and asynchronous snapshot bytes;
        # Rust remains the document compiler and resident admission authority.
        "src/codex_plugin_scanner/guard/native_policy_snapshot_codec.py",
        "src/codex_plugin_scanner/guard/native_business_source_bridge.py",
        "src/codex_plugin_scanner/guard/native_business_source_anchor_bridge.py",
        "src/codex_plugin_scanner/guard/native_business_source_store.py",
        "src/codex_plugin_scanner/guard/native_business_source_retention.py",
        "src/codex_plugin_scanner/guard/config.py",
        # Stat-keyed memo inputs for the native Guard-config loader; Rust owns
        # the parse, trust checks and every resulting value.
        "src/codex_plugin_scanner/guard/native_guard_config.py",
        "src/codex_plugin_scanner/guard/config_file_io.py",
        "src/codex_plugin_scanner/guard/directory_path_authority.py",
        "src/codex_plugin_scanner/guard/path_resolution_cache.py",
        "src/codex_plugin_scanner/guard/runtime/command_activity_correlation.py",
    }
)
_PERSISTENCE_PATH_PREFIXES: Final = (
    "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/local_dashboard_session.py",
    "src/codex_plugin_scanner/guard/guard_home_state.py",
    "src/codex_plugin_scanner/guard/store_base.py",
    "src/codex_plugin_scanner/guard/store_mcp_catalog.py",
    "src/codex_plugin_scanner/guard/store_storage_gate.py",
)
_PRESENTATION_PATHS: Final = frozenset(
    {
        # Retained Python: approval presentation, harness adapters, and
        # continuation surfaces. These render or forward decisions; they
        # never compute them.
        "src/codex_plugin_scanner/guard/adapters/cursor_native_approval.py",
        "src/codex_plugin_scanner/guard/adapters/zcode_contained_tests.py",
        "src/codex_plugin_scanner/guard/approval_scope_support.py",
        "src/codex_plugin_scanner/guard/approvals.py",
        "src/codex_plugin_scanner/guard/codex_app_server.py",
        "src/codex_plugin_scanner/guard/continuation_runtime.py",
        "src/codex_plugin_scanner/guard/edge_events.py",
        "src/codex_plugin_scanner/guard/harness_usage.py",
        "src/codex_plugin_scanner/guard/local_authority_integrity.py",
        "src/codex_plugin_scanner/guard/mcp_tool_calls.py",
        "src/codex_plugin_scanner/guard/temporary_mcp_approvals.py",
    }
)
_SERVICE_PATHS: Final = frozenset(
    {
        # Retained Python: daemon supervision/lifecycle, cloud/OAuth/network
        # services, publication, and install support.
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
        "src/codex_plugin_scanner/guard/daemon/lifecycle_journal.py",
        "src/codex_plugin_scanner/guard/daemon/manager.py",
        "src/codex_plugin_scanner/guard/daemon/manager_ephemeral_reap.py",
        "src/codex_plugin_scanner/guard/daemon/manager_process_query.py",
        "src/codex_plugin_scanner/guard/daemon/runtime_peer.py",
        "src/codex_plugin_scanner/guard/daemon/start_classification.py",
        "src/codex_plugin_scanner/guard/frozen_daemon_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_connection_identity.py",
        "src/codex_plugin_scanner/guard/extension_builder/io.py",
        "src/codex_plugin_scanner/guard/frozen_runtime_commands.py",
        "src/codex_plugin_scanner/guard/live_process_identity.py",
        "src/codex_plugin_scanner/guard/mdm/acl.py",
        "src/codex_plugin_scanner/guard/mdm/network_credentials.py",
        "src/codex_plugin_scanner/guard/mdm/network_transport.py",
        "src/codex_plugin_scanner/guard/mdm/network_trust.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_key.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_windows_support.py",
        "src/codex_plugin_scanner/guard/oauth_token_claims.py",
        "src/codex_plugin_scanner/guard/stable_guard_cli.py",
    }
)
_PENDING_AUTHORITY_PATHS: Final = frozenset(
    {
        # Decision-adjacent Python that remains authoritative until the
        # package/archive, guarded-launch, command-authority, and local-MCP
        # migration legs land. Each leg must shrink this set; it may only
        # grow through an explicit contract change.
        #
        # Every entry has to name a module the gate still reaches from a hook
        # root. A waiver for a module the hook graph no longer reaches excuses
        # nothing, and leaving it here would let the set read as a backlog
        # long after the leg that owned it landed, so the gate rejects a stale
        # entry rather than trusting this list to be pruned by hand.
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_floor.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_prepare.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_paths.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_artifacts.py",
        "src/codex_plugin_scanner/guard/runtime/approval_context.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_authorization.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_skill_firewall.py",
        "src/codex_plugin_scanner/guard/shims.py",
    }
)
_PERSISTENCE_ONLY_PATHS: Final[frozenset[str]] = frozenset()
