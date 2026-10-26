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
}
