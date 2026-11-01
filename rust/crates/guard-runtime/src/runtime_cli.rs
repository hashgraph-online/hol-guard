use super::*;

pub(super) fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, flag] if command == "context-assistance-install-operator" && flag == "--stdin" => {
            let response = policy_store::context_assistance_registry::run_operator_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "context-assistance-enroll-local" && flag == "--stdin" => {
            let response = policy_store::context_assistance_registry::run_enroll_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "pack-lifecycle" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&pack_lifecycle::run(&bytes)?)
        }
        [command, ..] if command == "restricted-linux-launch" => {
            let digest = if args.len() == 2 { args[1].as_str() } else { "" };
            std::process::exit(restricted_linux_launch::launch(digest))
        }
        #[cfg(unix)]
        [command, rest @ ..] if command == contained_workspace_sink::SINK_COMMAND => {
            std::process::exit(contained_workspace_sink::run(rest))
        }
        #[cfg(unix)]
        [command, rest @ ..] if command == contained_workspace_sink::LAUNCH_COMMAND => {
            std::process::exit(contained_workspace_sink::launch(rest))
        }
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => {
            write_json(&capabilities())
        }
        [command] if command == "rule-contract" => write_json(&guard_rule_contract::rule_contract()),
        [command, flag] if command == "rule-contract" && flag == "--json" => {
            write_json(&guard_rule_contract::rule_contract())
        }
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, mode, marker, config]
            if command == "claude-hook-bridge"
                && mode == claude_session_start::SESSION_START_MODE
                && marker == claude_session_start::SESSION_START_MARKER =>
        {
            std::process::exit(claude_session_start::run(config))
        }
        [command, marker, config]
            if command == "claude-hook-bridge" && marker == claude_hook_bridge::BRIDGE_MARKER =>
        {
            claude_hook_bridge::run(config)
        }
        // The hook carries its config as the last argument. Installs made
        // before the Python bridge became a launcher pass the whole Python
        // argv ahead of it, so both shapes reach the same bridge.
        [command, python_argv @ ..]
            if command == codex_hook_bridge::BRIDGE_COMMAND && !python_argv.is_empty() =>
        {
            std::process::exit(codex_hook_bridge::run(python_argv))
        }
        [command, python_argv @ ..]
            if command == bounded_hook_bridge::BRIDGE_COMMAND && python_argv.len() >= 2 =>
        {
            std::process::exit(bounded_hook_bridge::run(python_argv))
        }
        [command, python_argv @ ..]
            if command == cursor_hook_bridge::BRIDGE_COMMAND && python_argv.len() >= 2 =>
        {
            std::process::exit(cursor_hook_bridge::run(python_argv))
        }
        [command, config] if command == cline_hook_worker::WORKER_COMMAND => {
            std::process::exit(cline_hook_worker::run(config))
        }
        [command, config] if command == pi_hook_bridge::BRIDGE_COMMAND => {
            std::process::exit(pi_hook_bridge::run(config))
        }
        [command, python_argv @ ..]
            if command == mcp_relay::RELAY_COMMAND && python_argv.len() >= 2 =>
        {
            std::process::exit(mcp_relay::run(python_argv))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "native-bash-host-context" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_bytes_response(&native_exact_action_op::observe_bash_host_bytes(&bytes)?)
        }
        [command, flag] if policy_snapshot_build::is_command(command) && flag == "--stdin" => {
            let response = policy_snapshot_build::run_command(command, io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if contained_output_match::is_command(command) && flag == "--stdin" => {
            let response = contained_output_match::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if desktop_core_onedir::is_command(command) && flag == "--stdin" => {
            let response = desktop_core_onedir::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if codex_hook_trust::is_command(command) && flag == "--stdin" => {
            let response = codex_hook_trust::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if desktop_notification::is_command(command) && flag == "--stdin" => {
            let response = desktop_notification::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if hook_removal_sweep::is_command(command) && flag == "--stdin" => {
            let response = hook_removal_sweep::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if macos_code_signing::is_command(command) && flag == "--stdin" => {
            let response = macos_code_signing::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if policy_file_io::is_command(command) && flag == "--stdin" => {
            let response = policy_file_io::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if removal_evidence::is_command(command) && flag == "--stdin" => {
            let response = removal_evidence::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if agent_safety_guidance::is_command(command) && flag == "--stdin" => {
            let response = agent_safety_guidance::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if grok_executable::is_command(command) && flag == "--stdin" => {
            let response = grok_executable::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if harness_coverage_command::is_command(command) && flag == "--stdin" => {
            let response = harness_coverage_command::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if health_lease_contract::is_command(command) && flag == "--stdin" => {
            let response = health_lease_contract::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if health_snapshot_binding::is_command(command) && flag == "--stdin" => {
            let response = health_snapshot_binding::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if supervisor_verdict::is_command(command) && flag == "--stdin" => {
            let response = supervisor_verdict::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if guard_config_load::is_command(command) && flag == "--stdin" => {
            let response = guard_config_load::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if guard_config_update::is_command(command) && flag == "--stdin" => {
            let response = guard_config_update::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if guard_config_resolve::is_command(command) && flag == "--stdin" => {
            let response = guard_config_resolve::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if installation_continuity::is_command(command) && flag == "--stdin" => {
            let response = installation_continuity::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if managed_policy_load_command::is_command(command) && flag == "--stdin" => {
            let response = managed_policy_load_command::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if health_lease_state::is_command(command) && flag == "--stdin" => {
            let response = health_lease_state::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if user_health_state::is_command(command) && flag == "--stdin" => {
            let response = user_health_state::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if hermes_file_inspect::is_command(command) && flag == "--stdin" => {
            let response = hermes_file_inspect::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if local_authority_integrity_op::is_command(command) && flag == "--stdin" => {
            let response = local_authority_integrity_op::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if store_quarantine_forensics::is_command(command) && flag == "--stdin" => {
            let response = store_quarantine_forensics::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if network_status_validation::is_command(command) && flag == "--stdin" => {
            let response = network_status_validation::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if local_skill_index::is_command(command) && flag == "--stdin" => {
            let response = local_skill_index::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if windows_private_state::is_command(command) && flag == "--stdin" => {
            let response = windows_private_state::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if onefile_extraction_reclaim::is_command(command) && flag == "--stdin" => {
            let response = onefile_extraction_reclaim::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if device_key_helper::is_command(command) && flag == "--stdin" => {
            let response = device_key_helper::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if desktop_foreign_installs::is_command(command) && flag == "--stdin" => {
            let response = desktop_foreign_installs::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if posix_processes::is_command(command) && flag == "--stdin" => {
            let response = posix_processes::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag]
            if windows_process_command_lines::is_command(command) && flag == "--stdin" =>
        {
            let response = windows_process_command_lines::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if policy_effective::is_command(command) && flag == "--stdin" => {
            let response = policy_effective::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if windows_process_lifecycle::is_command(command) && flag == "--stdin" => {
            let response = windows_process_lifecycle::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag]
            if windows_trusted_directories::is_command(command) && flag == "--stdin" =>
        {
            let response = windows_trusted_directories::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag]
            if release_manifest_verify_command::is_command(command) && flag == "--stdin" =>
        {
            let response = release_manifest_verify_command::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if system_proxies::is_command(command) && flag == "--stdin" => {
            let response = system_proxies::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if proxy_credentials::is_command(command) && flag == "--stdin" => {
            let response = proxy_credentials::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if native_install_verdict::is_command(command) && flag == "--stdin" => {
            let response = native_install_verdict::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if ownership_acl_verdict::is_command(command) && flag == "--stdin" => {
            let response = ownership_acl_verdict::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if business_source_codec::is_command(command) && flag == "--stdin" => {
            let response = business_source_codec::run_command(command, io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if mdm_integrity_snapshot::is_command(command) && flag == "--stdin" => {
            let response = mdm_integrity_snapshot::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if orphaned_worker_reap::is_command(command) && flag == "--stdin" => {
            let response = orphaned_worker_reap::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if runtime_fingerprint::is_command(command) && flag == "--stdin" => {
            let response = runtime_fingerprint::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if process_identity::is_command(command) && flag == "--stdin" => {
            let response = process_identity::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if local_risk_report::is_command(command) && flag == "--stdin" => {
            let response = local_risk_report::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if storage_retention::is_command(command) && flag == "--stdin" => {
            let response = storage_retention::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if sqlite_store_salvage::is_command(command) && flag == "--stdin" => {
            let response = sqlite_store_salvage::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if guard_home_resolve::is_command(command) && flag == "--stdin" => {
            let response = guard_home_resolve::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if hook_launch_scan::is_command(command) && flag == "--stdin" => {
            let response = hook_launch_scan::run_command(io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "compile-business-policy" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&business_document_compile::compile_bytes(&bytes)?)
        }
        [command, state_flag, state_dir]
            if command == "migrate-policy"
                && state_flag == "--state-dir" =>
        {
            let runtime_identity = resident_state::runtime_digest()?;
            policy_store::PolicySnapshotStore::migrate_legacy_state(
                std::path::Path::new(state_dir),
                &runtime_identity,
            )
        }
        [command, state_flag, state_dir, record_flag, record_path]
            if command == "enroll-approval-authority"
                && state_flag == "--state-dir"
                && record_flag == "--record" =>
        {
            policy_store::approval_authority::install_record(
                std::path::Path::new(state_dir),
                std::path::Path::new(record_path),
            )
        }
        [command, state_flag, state_dir, record_flag, record_path]
            if command == "enroll-approval-v4-authority"
                && state_flag == "--state-dir"
                && record_flag == "--record" =>
        {
            policy_store::approval_v4_authority::install_record(
                std::path::Path::new(state_dir),
                std::path::Path::new(record_path),
            )
        }
        [command, state_flag, state_dir, record_flag, record_path]
            if command == "enroll-workspace-review-authority"
                && state_flag == "--state-dir"
                && record_flag == "--record" =>
        {
            policy_store::workspace_review_authority::install_record(
                std::path::Path::new(state_dir),
                std::path::Path::new(record_path),
            )
        }
        [command, state_flag, state_dir, rp_flag, rp_id, origin_flag, origin]
            if command == "prepare-approval-v4-enrollment"
                && state_flag == "--state-dir"
                && rp_flag == "--rp-id"
                && origin_flag == "--origin" =>
        {
            let request = policy_store::approval_v4_authority::prepare_enrollment(
                std::path::Path::new(state_dir),
                rp_id,
                origin,
            )?;
            write_bytes_response(&request)
        }
        [command, state_flag, state_dir]
            if command == "prepare-approval-enrollment" && state_flag == "--state-dir" =>
        {
            let request = policy_store::approval_authority::prepare_enrollment(
                std::path::Path::new(state_dir),
            )?;
            write_bytes_response(&request)
        }
        #[cfg(target_os = "macos")]
        [command, flag, state_dir, owner_flag, owner_pid]
            if command == "native-bash-execute-client" && flag == "--stdin" && owner_flag == "--host-owner-pid" => {
            let pid = owner_pid.parse::<u32>().map_err(|_| "native_bash_host_owner_unavailable")?;
            let response = native_bash_client::run(std::path::Path::new(state_dir), read_stdin_bounded()?, Some(pid))?;
            write_bytes_response(&response)
        }
        #[cfg(target_os = "macos")]
        [command, flag, state_dir] if command == "native-bash-execute-client" && flag == "--stdin" => {
            let response = native_bash_client::run(std::path::Path::new(state_dir), read_stdin_bounded()?, None)?;
            write_bytes_response(&response)
        }
        [command, flag, state_dir]
            if matches!(command.as_str(), "hook-client" | "resident-client")
                && flag == "--stdin" =>
        {
            let bytes = read_stdin_bounded()?;
            if let Err(error) = strict_json_value(&bytes) {
                return write_bytes_response(&resident_protocol::safe_error_response(&error, false));
            }
            let timeout = managed_resident::client_timeout(&bytes);
            let response = managed_resident::client_request(
                std::path::Path::new(state_dir),
                &bytes,
                timeout,
            )?;
            write_bytes_response(&response)
        }
        [command, flag, state_dir]
            if command == "resident-client-stream" && flag == "--stdin" =>
        {
            managed_resident::client_stream(std::path::Path::new(state_dir))
        }
        [command, flag, state_dir, retire_flag]
            if command == "resident-stop"
                && flag == "--state-dir"
                && retire_flag == "--retire-clients" =>
        {
            managed_resident::stop_managed(std::path::Path::new(state_dir), true)
        }
        [command, flag, state_dir] if command == "resident-stop" && flag == "--state-dir" => {
            managed_resident::stop_managed(std::path::Path::new(state_dir), false)
        }
        [command, flag, state_dir] if command == "resident-prewarm" && flag == "--state-dir" => {
            managed_resident::prewarm(std::path::Path::new(state_dir))
        }
        [command, flag, state_dir]
            if command == "resident-reset-restart-budget" && flag == "--state-dir" =>
        {
            managed_resident::reset_restart_budget(std::path::Path::new(state_dir))
        }
        [command, flag, state_dir] if command == "resident-health" && flag == "--state-dir" => {
            let health = managed_resident::lifecycle_health(std::path::Path::new(state_dir))?;
            write_json(&serde_json::json!({"health": health}))
        }
        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "pre-tool" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_pre_tool_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        // Provisioning the policy verifier key cannot be a resident call: the
        // resident refuses to serve until that key exists. This one-shot arm
        // is the bootstrap, so the master arrives on stdin and never on argv,
        // where another local process could read it.
        [command, flag, state_dir]
            if command == "provision-verifier-key" && flag == "--stdin" =>
        {
            let bytes = read_stdin_bounded()?;
            let request = strict_json_value(&bytes)?;
            let encoded = request
                .get("policy_integrity_key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "native_policy_verifier_master_invalid".to_owned())?;
            let master = zeroize::Zeroizing::new(
                hex::decode(encoded)
                    .map_err(|_| "native_policy_verifier_master_invalid".to_owned())?,
            );
            let outcome = policy_verifier_key_provision::provision_verifier_key(
                std::path::Path::new(state_dir),
                &master,
            )?;
            write_json(&serde_json::json!({
                "schema": "hol-guard-native-verifier-key.v1",
                "status": outcome.as_str(),
            }))
        }
        [command, flag, state_dir, request_flag, request_id]
            if command == "workspace-review-decision"
                && flag == "--stdin"
                && request_flag == "--request-id" =>
        {
            let bytes = read_stdin_bounded()?;
            let decision = strict_json_value(&bytes)?;
            let canonical = guard_policy_snapshot::canonical_json_bytes(&decision)
                .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
            if canonical != bytes {
                return Err("native_workspace_review_decision_noncanonical".to_owned());
            }
            let state_base = std::path::Path::new(state_dir);
            let runtime_identity = resident_state::runtime_digest()?;
            let policy_store = policy_store::PolicySnapshotStore::new_with_resident_generation(
                state_base,
                &runtime_identity,
                0,
            )?;
            let verified = policy_store::workspace_review_decision::verify_and_claim_request(
                &policy_store,
                request_id,
                &decision,
            )?;
            write_json(&serde_json::json!({
                "status": if verified.replayed { "replayed" } else { "verified" },
                "replayed": verified.replayed,
                "request_id": request_id,
                "decision": verified.decision,
                "claim_id": verified.claim_id,
                "authority_record_digest": verified.authority_record_digest,
                "request_binding": verified.request_binding,
                "action_binding": verified.action_binding,
                "intent_binding": verified.intent_binding,
                "revision_binding": verified.revision_binding,
                "policy_binding": verified.policy_binding,
                "retry_scope_binding": verified.retry_scope_binding,
                "request_snapshot_digest": verified.request_snapshot_digest,
                "envelope_digest": verified.envelope_digest,
            }))
        }
        [command, flag] if command == "archive-inspect" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = archive_inspect::evaluate_archive_inspection_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "content-decode" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = content_decode::evaluate_content_decode_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == runtime_identity::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&runtime_identity::run_command(&bytes)?)
        }
        [command, flag] if command == runtime_identity_probe::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&runtime_identity_probe::run_command(&bytes)?)
        }
        [command, flag] if command == secrets_cli::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&secrets_cli::run_command(&bytes)?)
        }
        [command, flag] if command == guard_plugin_kit::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&guard_plugin_kit::run_request(&bytes))
        }
        [command, flag] if command == guard_plugin_telemetry::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&guard_plugin_telemetry::run_request(&bytes))
        }
        [command, flag] if command == workspace_snapshot::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&workspace_snapshot::run_command(&bytes)?)
        }
        [command, flag]
            if command == workspace_snapshot::export_preview::COMMAND && flag == "--stdin" =>
        {
            let bytes = read_stdin_bounded()?;
            write_json(&workspace_snapshot::export_preview::run_command(&bytes)?)
        }
        [command, flag] if command == workspace_mcp_config::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&workspace_mcp_config::run_command(&bytes)?)
        }
        [command, flag] if command == workspace_fix::COMMAND && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            write_json(&workspace_fix::run_command(&bytes)?)
        }
        [command, flag] if command == "context-digest" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = context_digest::evaluate_context_digest_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => serve(path),
        [command, flag, address] if command == "serve" && flag == "--tcp-loopback" => {
            serve_loopback(address)
        }
        [
            command,
            state_flag,
            state_dir,
            generation_flag,
            generation,
            owner_flag,
            owner_process_id,
            digest_flag,
            digest,
        ]
            if command == "serve-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && owner_flag == "--owner-process-id"
                && digest_flag == "--runtime-sha256" =>
        {
            let result = managed_resident::serve_managed(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                managed_resident::parse_process_id(owner_process_id)?,
                digest,
            );
            mcp_stdio_session_op::close_all_sessions();
            result
        }
        [command, state_flag, state_dir, generation_flag, generation, digest_flag, digest]
            if command == "supervise-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && digest_flag == "--runtime-sha256" =>
        {
            managed_resident::supervise_managed(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                digest,
            )
        }
        [
            command,
            state_flag,
            state_dir,
            generation_flag,
            generation,
            owner_flag,
            owner_process_id,
            digest_flag,
            digest,
        ]
            if command == "supervise-managed"
                && state_flag == "--state-dir"
                && generation_flag == "--generation"
                && owner_flag == "--owner-process-id"
                && digest_flag == "--runtime-sha256" =>
        {
            managed_resident::supervise_managed_for_owner(
                std::path::Path::new(state_dir),
                managed_resident::parse_generation(generation)?,
                digest,
                managed_resident::parse_process_id(owner_process_id)?,
            )
        }
        _ => Err(
            "usage: hol-guard-runtime compile-business-policy --stdin | capabilities --json | rule-contract --json | self-test --json | hook --stdin | migrate-policy --state-dir STATE_DIR | prepare-approval-enrollment --state-dir STATE_DIR | enroll-approval-authority --state-dir STATE_DIR --record RECORD | prepare-approval-v4-enrollment --state-dir STATE_DIR --rp-id RP_ID --origin ORIGIN | enroll-approval-v4-authority --state-dir STATE_DIR --record RECORD | enroll-workspace-review-authority --state-dir STATE_DIR --record RECORD | workspace-review-decision --stdin STATE_DIR --request-id REQUEST_ID | hook-client --stdin STATE_DIR | resident-client --stdin STATE_DIR | resident-client-stream --stdin STATE_DIR | command-model --stdin | pre-tool --stdin | archive-inspect --stdin | content-decode --stdin | secrets-cli --stdin | context-digest --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT | resident-stop --state-dir STATE_DIR [--retire-clients] | resident-prewarm --state-dir STATE_DIR | resident-reset-restart-budget --state-dir STATE_DIR | resident-health --state-dir STATE_DIR | serve-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA | supervise-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA"
                .into(),
        ),
    }
}
