use super::*;

pub(super) fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
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
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = oneshot::evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if policy_snapshot_build::is_command(command) && flag == "--stdin" => {
            let response = policy_snapshot_build::run_command(command, io::stdin().lock())?;
            write_bytes_response(&response)
        }
        [command, flag] if business_source_codec::is_command(command) && flag == "--stdin" => {
            let response = business_source_codec::run_command(command, io::stdin().lock())?;
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
            "usage: hol-guard-runtime compile-business-policy --stdin | capabilities --json | rule-contract --json | self-test --json | hook --stdin | migrate-policy --state-dir STATE_DIR | prepare-approval-enrollment --state-dir STATE_DIR | enroll-approval-authority --state-dir STATE_DIR --record RECORD | prepare-approval-v4-enrollment --state-dir STATE_DIR --rp-id RP_ID --origin ORIGIN | enroll-approval-v4-authority --state-dir STATE_DIR --record RECORD | enroll-workspace-review-authority --state-dir STATE_DIR --record RECORD | workspace-review-decision --stdin STATE_DIR --request-id REQUEST_ID | hook-client --stdin STATE_DIR | resident-client --stdin STATE_DIR | resident-client-stream --stdin STATE_DIR | command-model --stdin | pre-tool --stdin | archive-inspect --stdin | context-digest --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT | resident-stop --state-dir STATE_DIR [--retire-clients] | serve-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA | supervise-managed --state-dir STATE_DIR --generation N --owner-process-id PID --runtime-sha256 SHA"
                .into(),
        ),
    }
}
