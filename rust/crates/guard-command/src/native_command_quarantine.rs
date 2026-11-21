//! Tightening-only routing from authenticated compiler output. Author-facing
//! executable declarations are deliberately not consulted. Unknown/opaque
//! launches and unindexed rules require a broad, explicit quarantine.
use super::*;

impl CompiledNativeCommandControls {
    pub(super) fn enforce_quarantine(
        &self,
        command: Option<&CanonicalCommandV1>,
        tool: Option<&str>,
        result: &mut PreToolResultV1,
    ) {
        // Submitting a prompt runs nothing. The quarantine covers an active
        // command collection, and every execution a prompt leads to is judged
        // on its own arrival, so holding the prompt itself protects nothing and
        // locks the operator out of the only session that could install the
        // verified replacement this block asks for.
        //
        // The action type alone does not prove that. `infer_action_type` also
        // types a named tool as a prompt whenever its name carries a prompt
        // word -- `spawn_subagent`, `send_message`, `ask_user` -- and those are
        // PreToolUse calls that do run something. An owner-less arrival is what
        // proves nothing executes here: a real submission carries neither a
        // parsed command nor a tool name, and every tool call keeps the broad
        // quarantine it had before.
        if result.action.action_type == PreToolActionTypeV1::Prompt
            && command.is_none()
            && tool.is_none()
        {
            return;
        }
        if !self.quarantine_applies(command, tool) {
            return;
        }
        result.minimum_action = "block".into();
        result.policy_action = "block".into();
        result.decision = "deny".into();
        result.explicitly_benign = false;
        result.reason_code = "native_active_pack_quarantine".into();
        result.reason = "An active policy pack is quarantined by authenticated security metadata. A verified replacement is required.".into();
    }
    pub fn set_security_quarantine(
        &mut self,
        pending: bool,
        ids: &BTreeSet<String>,
    ) -> Result<(), &'static str> {
        if ids.iter().any(|id| {
            !self
                .program
                .extensions
                .iter()
                .any(|e| &e.extension_id == id)
        }) {
            return Err("native_active_pack_quarantine_owner_missing");
        }
        self.quarantine_pending = pending;
        self.quarantine_index =
            (!ids.is_empty()).then(|| CommandCandidateIndex::for_active(&self.program, ids));
        Ok(())
    }

    pub(super) fn quarantine_applies(
        &self,
        command: Option<&CanonicalCommandV1>,
        tool: Option<&str>,
    ) -> bool {
        if self.quarantine_pending {
            return true;
        }
        let Some(index) = &self.quarantine_index else {
            return false;
        };
        let Some(command) = command else {
            // A tool name alone cannot prove a server's package/transport
            // identity: arbitrary aliases and server-level permissions can
            // cover every tool. Until that identity is authenticated here,
            // non-shell quarantine is global, including all MCP tools.
            let _ = tool;
            return true;
        };
        if command.confidence != "exact"
            || command.uncertainty_reason.is_some()
            || command.path_overridden
            || !command.wrapper_chain.is_empty()
            || command.segments.iter().any(|s| {
                !s.wrapper_chain.is_empty()
                    || s.executable.as_deref().is_none_or(|exe| {
                        matches!(
                            exe.rsplit(['/', '\\'])
                                .next()
                                .unwrap_or(exe)
                                .to_ascii_lowercase()
                                .as_str(),
                            "sh" | "bash"
                                | "zsh"
                                | "fish"
                                | "pwsh"
                                | "powershell"
                                | "cmd"
                                | "env"
                                | "sudo"
                                | "xargs"
                                | "timeout"
                                | "nohup"
                                | "python"
                                | "python3"
                                | "node"
                                | "ruby"
                                | "perl"
                        )
                    })
            })
        {
            return true;
        }
        !index.candidates(command).is_empty()
            || index
                .extension_indices()
                .iter()
                .any(|&i| self.program.extensions[i].delegated_protection.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quarantine_covers_exhaustive_fixture_owners_compounds_and_wrappers() {
        let program = crate::native_command_program::authored_test_support::full_program();
        let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
            "schema":"guard.native-command-control-binding.v1", "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,
            "health":"protected","revision":1,"managed_revision":0,"effective_digest":"", "layers":[]
        })).unwrap();
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        let mut controls =
            CompiledNativeCommandControls::for_program(&binding, program.clone()).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native-command-observations-v1.json"
        ))
        .unwrap();
        let mut checked = 0;
        for case in fixture["cases"].as_array().unwrap() {
            let command: CanonicalCommandV1 =
                serde_json::from_value(case["model"].clone()).unwrap();
            for observation in case["observations"].as_array().unwrap() {
                let id = observation["extension_id"].as_str().unwrap().to_owned();
                controls
                    .set_security_quarantine(false, &BTreeSet::from([id.clone()]))
                    .unwrap();
                assert!(
                    controls.quarantine_applies(Some(&command), None),
                    "owner={id} command={command:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 100);
        let mcp = program
            .extensions
            .iter()
            .find(|extension| extension.mcp.is_some())
            .unwrap();
        controls
            .set_security_quarantine(false, &BTreeSet::from([mcp.extension_id.clone()]))
            .unwrap();
        for tool in [
            "mcp__renamed_server__read",
            "mcp__renamed_server__unknown",
            "mcp__other__write",
            "server/tool",
        ] {
            assert!(
                controls.quarantine_applies(None, Some(tool)),
                "MCP alias cannot narrow quarantine: {tool}"
            );
        }
        controls
            .set_security_quarantine(true, &BTreeSet::new())
            .unwrap();
        assert!(controls.quarantine_applies(None, Some("mcp__unknown__read")));
    }

    fn quarantined_result(action_type: &str, operation: &str, event: &str) -> PreToolResultV1 {
        serde_json::from_value(serde_json::json!({
            "schema": "guard-pre-tool-result.v1",
            "version": 1,
            "authority": "rust",
            "action": {
                "schema": "guard-pre-tool-action.v1",
                "version": 1,
                "harness": "claude-code",
                "event": event,
                "action_type": action_type,
                "operation": operation,
                "bounded": true,
                "sensitive_target": false
            },
            "decision": "allow",
            "policy_action": "allow",
            "minimum_action": "allow",
            "reason_code": "native_exact_safe_command",
            "reason": "The Rust command authority proved this bounded action explicitly benign.",
            "explicitly_benign": true
        }))
        .unwrap()
    }

    #[test]
    fn quarantine_holds_executions_and_releases_prompt_submission() {
        let program = crate::native_command_program::authored_test_support::full_program();
        let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
            "schema":"guard.native-command-control-binding.v1", "program_digest":program.program_digest,
            "catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,
            "health":"protected","revision":1,"managed_revision":0,"effective_digest":"", "layers":[]
        })).unwrap();
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        let owner = program
            .extensions
            .iter()
            .find(|extension| extension.mcp.is_some())
            .unwrap()
            .extension_id
            .clone();
        let mut controls = CompiledNativeCommandControls::for_program(&binding, program).unwrap();
        controls
            .set_security_quarantine(false, &BTreeSet::from([owner]))
            .unwrap();

        // A quarantined pack must not hold the prompt that submits the
        // operator's next instruction: nothing executes at that point, and the
        // block would close the only session able to install the replacement.
        let mut prompt = quarantined_result("prompt", "submit", "UserPromptSubmit");
        controls.enforce_quarantine(None, None, &mut prompt);
        assert_eq!(prompt.policy_action, "allow", "{prompt:?}");
        assert_eq!(prompt.decision, "allow", "{prompt:?}");
        assert_eq!(prompt.reason_code, "native_exact_safe_command");

        // The execution routes the quarantine exists for are unchanged.
        let mut mcp_call = quarantined_result("mcp_tool", "call", "PreToolUse");
        controls.enforce_quarantine(None, Some("mcp__renamed_server__read"), &mut mcp_call);
        assert_eq!(mcp_call.policy_action, "block", "{mcp_call:?}");
        assert_eq!(mcp_call.reason_code, "native_active_pack_quarantine");

        // A tool whose name carries a prompt word is typed as a prompt by
        // `infer_action_type`, but it is still a PreToolUse call that runs
        // something, so the quarantine holds it.
        for tool in ["spawn_subagent", "send_message", "ask_user"] {
            let mut call = quarantined_result("prompt", "submit", "PreToolUse");
            controls.enforce_quarantine(None, Some(tool), &mut call);
            assert_eq!(call.policy_action, "block", "{tool}: {call:?}");
            assert_eq!(call.decision, "deny", "{tool}: {call:?}");
            assert_eq!(call.reason_code, "native_active_pack_quarantine");
        }

        // A pending quarantine covers every owner, and still releases prompts.
        controls
            .set_security_quarantine(true, &BTreeSet::new())
            .unwrap();
        let mut pending_prompt = quarantined_result("prompt", "submit", "UserPromptSubmit");
        controls.enforce_quarantine(None, None, &mut pending_prompt);
        assert_eq!(pending_prompt.policy_action, "allow", "{pending_prompt:?}");
        let mut pending_command = quarantined_result("command", "execute", "PreToolUse");
        controls.enforce_quarantine(None, None, &mut pending_command);
        assert_eq!(
            pending_command.policy_action, "block",
            "{pending_command:?}"
        );
        assert_eq!(pending_command.reason_code, "native_active_pack_quarantine");
        let mut pending_tool = quarantined_result("prompt", "submit", "PreToolUse");
        controls.enforce_quarantine(None, Some("spawn_subagent"), &mut pending_tool);
        assert_eq!(pending_tool.policy_action, "block", "{pending_tool:?}");
        assert_eq!(pending_tool.reason_code, "native_active_pack_quarantine");
    }
}
