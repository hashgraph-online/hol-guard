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
_EQUIVALENCE_FUNCTIONS: Final = frozenset({"output_equivalent", "parity_signature", "sha256_text"})

_COMPATIBILITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/runtime/source_paths.py",
        "src/codex_plugin_scanner/guard/native_command_model.py",
    }
)
_TRANSPORT_IDENTITY_PATHS: Final = frozenset(
    {
        # Payload-reference metadata validation; the native edge reads bytes.
        "src/codex_plugin_scanner/guard/daemon/hook_request_parsing.py",
        # Archive-inspection transport: lease, request binding, and the
        # bounded native worker invocation; all archive semantics are Rust.
        "src/codex_plugin_scanner/guard/native_archive_inspection.py",
        "src/codex_plugin_scanner/guard/native_runtime.py",
        # Extracted binary identity validation; no command or policy semantics.
        "src/codex_plugin_scanner/guard/native_binary_identity.py",
        "src/codex_plugin_scanner/guard/native_context.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/native_runtime_resilience.py",
        "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py",
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
        "src/codex_plugin_scanner/guard/daemon/manager.py",
        # Interpreter bootstrap identity only; no policy or command decisions.
        "src/codex_plugin_scanner/guard/daemon/pipx_import_paths.py",
        "src/codex_plugin_scanner/guard/frozen_runtime_commands.py",
    }
)
_TRANSPORT_INTEGRITY_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_decision_receipt.py",
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
        # Retry lineage is local diagnostic metadata. Its digests protect
        # reattachment integrity but never authorize or evaluate an action.
        "src/codex_plugin_scanner/guard/retry_lineage.py",
    }
)
_TRANSPORT_AUTHORITY_PATHS: Final = frozenset(
    {
        # Strict owner-checked native command-control lock and marker transport.
        "src/codex_plugin_scanner/guard/native_command_control_authority_io.py",
    }
)
_TRANSPORT_DECODE_PATHS: Final = frozenset(
    {
        "src/codex_plugin_scanner/guard/native_hook_edge.py",
        "src/codex_plugin_scanner/guard/native_pretool.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        # Resident-op dispatch bridge: decodes the bounded native response and
        # returns a DTO; it does not interpret response content into a decision.
        "src/codex_plugin_scanner/guard/native_execution.py",
        # Bounded response decoding for native package-authority results.
        "src/codex_plugin_scanner/guard/native_package_authority.py",
        # Decodes the bounded resident approval-reuse response envelope.
        "src/codex_plugin_scanner/guard/native_approval_reuse.py",
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
        # Native-authenticated source binding and asynchronous snapshot bytes;
        # Rust remains the document compiler and resident admission authority.
        "src/codex_plugin_scanner/guard/native_policy_snapshot_codec.py",
        "src/codex_plugin_scanner/guard/native_business_source_bridge.py",
        "src/codex_plugin_scanner/guard/native_business_source_anchor_bridge.py",
        "src/codex_plugin_scanner/guard/native_business_source_store.py",
        "src/codex_plugin_scanner/guard/native_business_source_retention.py",
        "src/codex_plugin_scanner/guard/config.py",
        "src/codex_plugin_scanner/guard/config_file_io.py",
        "src/codex_plugin_scanner/guard/directory_path_authority.py",
        "src/codex_plugin_scanner/guard/runtime/command_activity_correlation.py",
    }
)
_PERSISTENCE_PATH_PREFIXES: Final = (
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py",
    "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
    "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/local_dashboard_session.py",
    "src/codex_plugin_scanner/guard/guard_home_state.py",
    "src/codex_plugin_scanner/guard/store_base.py",
    "src/codex_plugin_scanner/guard/store_mcp_catalog.py",
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
        "src/codex_plugin_scanner/guard/daemon/hook_pretool_rendering.py",
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
        "src/codex_plugin_scanner/guard/runtime/supply_chain_package_services.py",
    }
)
_PENDING_AUTHORITY_PATHS: Final = frozenset(
    {
        # Decision-adjacent Python that remains authoritative until the
        # package/archive, guarded-launch, command-authority, and local-MCP
        # migration legs land. Each leg must shrink this set; it may only
        # grow through an explicit contract change.
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_eval.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_floor.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_generic.py",
        "src/codex_plugin_scanner/guard/cli/commands_hook_native_prepare.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_apply_patch_policy.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_commands.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_git.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_git_config.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_paths.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_prompt_attachments.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_reads.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_codex_tool_output.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_hook_state.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_native_search.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_artifacts.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_policy.py",
        "src/codex_plugin_scanner/guard/cli/commands_support_runtime_resolution.py",
        "src/codex_plugin_scanner/guard/package_execution_context.py",
        "src/codex_plugin_scanner/guard/package_execution_context_configuration.py",
        "src/codex_plugin_scanner/guard/package_execution_context_inputs.py",
        "src/codex_plugin_scanner/guard/package_shim_frozen.py",
        "src/codex_plugin_scanner/guard/package_shim_status.py",
        "src/codex_plugin_scanner/guard/runtime/_shell_execution_context_support.py",
        "src/codex_plugin_scanner/guard/runtime/_shell_secret_read_support.py",
        "src/codex_plugin_scanner/guard/runtime/actions.py",
        "src/codex_plugin_scanner/guard/runtime/approval_context.py",
        "src/codex_plugin_scanner/guard/runtime/browser_mcp_intent.py",
        "src/codex_plugin_scanner/guard/runtime/command_decision_adapter.py",
        "src/codex_plugin_scanner/guard/runtime/command_evaluation.py",
        "src/codex_plugin_scanner/guard/runtime/compound_git_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/contained_execution_common.py",
        "src/codex_plugin_scanner/guard/runtime/containment_executor.py",
        "src/codex_plugin_scanner/guard/runtime/direct_typescript_diagnostics.py",
        "src/codex_plugin_scanner/guard/runtime/direct_vitest.py",
        "src/codex_plugin_scanner/guard/runtime/effect_decision.py",
        "src/codex_plugin_scanner/guard/runtime/embedded_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/extension_contribution.py",
        "src/codex_plugin_scanner/guard/runtime/extension_control_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/extension_trust.py",
        "src/codex_plugin_scanner/guard/runtime/false_positive_rules.py",
        "src/codex_plugin_scanner/guard/runtime/git_execution_safety.py",
        "src/codex_plugin_scanner/guard/runtime/git_index_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/github_actions_read_workflow.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_approval_record.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_authorization.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_context.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_operations.py",
        "src/codex_plugin_scanner/guard/runtime/github_workflow_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/jsonc.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_commands.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_compound.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_identity.py",
        "src/codex_plugin_scanner/guard/runtime/local_cli_runner.py",
        "src/codex_plugin_scanner/guard/runtime/local_package_script_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/lockfile_evaluation_support.py",
        "src/codex_plugin_scanner/guard/runtime/lockfile_parse_result.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_protection.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_server_contribution.py",
        "src/codex_plugin_scanner/guard/runtime/mcp_skill_firewall.py",
        "src/codex_plugin_scanner/guard/runtime/npm_source_spec.py",
        "src/codex_plugin_scanner/guard/runtime/package_evidence_common.py",
        "src/codex_plugin_scanner/guard/runtime/package_intent_common.py",
        "src/codex_plugin_scanner/guard/runtime/package_intent_parser.py",
        "src/codex_plugin_scanner/guard/runtime/package_json_scripts.py",
        "src/codex_plugin_scanner/guard/runtime/package_manifest_diff.py",
        "src/codex_plugin_scanner/guard/runtime/prompt_injection.py",
        "src/codex_plugin_scanner/guard/runtime/read_only_git_audit.py",
        "src/codex_plugin_scanner/guard/runtime/restricted_archive_destination.py",
        "src/codex_plugin_scanner/guard/runtime/restricted_archive_stream.py",
        "src/codex_plugin_scanner/guard/runtime/routine_local_node.py",
        "src/codex_plugin_scanner/guard/runtime/routine_node_identity.py",
        "src/codex_plugin_scanner/guard/runtime/routine_setup_commands.py",
        "src/codex_plugin_scanner/guard/runtime/runner.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/agent_guidance_reads.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/benign_requests.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/credential_exfiltration.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/developer_inspection.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/developer_routines.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/git_routines.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_launch.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_observers.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/interpreter_trust.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/local_read_operands.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/request_artifacts.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/routine_directory_creation.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/sensitive_read_pipeline.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/shell_quote_parsing.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/shell_static_safety.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/source_edit_context.py",
        "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/tool_action_requests.py",
        "src/codex_plugin_scanner/guard/runtime/shell_command_wrappers.py",
        "src/codex_plugin_scanner/guard/runtime/shell_secret_reads.py",
        "src/codex_plugin_scanner/guard/runtime/skill_paths.py",
        "src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_runtime.py",
        "src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py",
        "src/codex_plugin_scanner/guard/runtime/typescript_launch_evidence.py",
        "src/codex_plugin_scanner/guard/runtime/workspace_path_guard.py",
        "src/codex_plugin_scanner/guard/shims.py",
        "src/codex_plugin_scanner/guard/trusted_local_tools.py",
        "src/codex_plugin_scanner/guard/trusted_package_tools.py",
    }
)
_PERSISTENCE_ONLY_PATHS: Final = frozenset(
    {
        # Opt-in sealed diagnostics; these helpers never authorize a decision.
        "src/codex_plugin_scanner/guard/codex_binding_capture.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_bounds.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_crypto.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_fs.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_join.py",
        "src/codex_plugin_scanner/guard/codex_binding_capture_writer.py",
    }
)
