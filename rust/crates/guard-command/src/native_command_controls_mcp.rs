//! MCP decisions share the authenticated, immutable active command collection.

use super::CompiledNativeCommandControls;
use crate::contributed_mcp_decision::{
    contributions, decide_active_contribution, matching_contribution, ContributedMcpInput,
    ContributedMcpOutcome, CONTRIBUTED_MCP_SOURCE,
};

impl CompiledNativeCommandControls {
    /// Request layers are not activation authority. The collection, activation,
    /// disabled permissions and quarantine were bound on snapshot admission.
    pub fn decide_contributed_mcp(
        &self,
        input: &ContributedMcpInput<'_>,
    ) -> Option<ContributedMcpOutcome> {
        let blocked = || {
            (input.current_action != "block").then_some(ContributedMcpOutcome {
                action: "block",
                source: CONTRIBUTED_MCP_SOURCE,
                reason: "This MCP tool is blocked by its authenticated extension authority.",
            })
        };
        // MCP identity fields cannot narrow the existing non-shell quarantine
        // floor. Unknown aliases are held just like named server tools.
        if self.global_block || self.quarantine_applies(None, None) {
            return blocked();
        }
        let active: Vec<_> = contributions(&self.program)
            .into_iter()
            .filter(|item| self.active_extensions.contains(item.catalog_id))
            .collect();
        let contribution = matching_contribution(&active, input)?;
        let extension = self
            .program
            .extensions
            .iter()
            .find(|extension| extension.extension_id == contribution.catalog_id)?;
        if self.blocked_extensions.contains(contribution.catalog_id)
            || extension
                .permissions
                .iter()
                .any(|permission| self.blocked_permissions.contains(&permission.permission_id))
        {
            return blocked();
        }
        decide_active_contribution(contribution, input, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_command_program::authored_test_support::full_program;
    use guard_contracts::NativeCommandControlBindingV1;
    use serde_json::json;
    use std::collections::BTreeSet;

    fn controls(enabled: bool, permission_disabled: bool) -> CompiledNativeCommandControls {
        let program = full_program();
        let mut intent = vec![];
        if enabled {
            for id in ["command.mcp-filesystem", "command.mcp-enola"] {
                intent.push(json!({"target_kind":"extension","target_id":id,"state":"enabled"}));
            }
        }
        if permission_disabled {
            let filesystem = program
                .extensions
                .iter()
                .find(|extension| extension.extension_id == "command.mcp-filesystem")
                .unwrap();
            intent.push(json!({"target_kind":"permission", "target_id":filesystem.permissions[0].permission_id,"state":"disabled"}));
        }
        let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
            "schema":"guard.native-command-control-binding.v1",
            "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,
            "trust_digest":program.trust_digest,"health":"protected","revision":1,"managed_revision":0,
            "effective_digest":"", "layers":[{"schema_version":"1.0.0","kind":"local-admin",
                "catalog_digest":program.catalog_digest,"global_lockdown":false,"controls":intent}]
        })).unwrap();
        binding.effective_digest = binding.compute_effective_digest().unwrap();
        CompiledNativeCommandControls::for_program(&binding, program).unwrap()
    }

    fn decide(
        controls: &CompiledNativeCommandControls,
        enola: bool,
        action: &str,
    ) -> Option<ContributedMcpOutcome> {
        let identity = json!({"package_name":if enola {"enola-cli"} else {"@modelcontextprotocol/server-filesystem"},
            "command":if enola {"uvx"} else {"npx"}, "transport":"stdio", "package_source":"default",
            "package_version":null,"env_keys":[]});
        let tool = json!(if enola { "query_facts" } else { "write_file" });
        controls.decide_contributed_mcp(&ContributedMcpInput {
            current_action: action,
            server_identity: identity.as_object(),
            artifact_transport: None,
            server_name: None,
            tool_name: Some(&tool),
            layers: &[],
        })
    }

    #[test]
    fn authenticated_active_collection_decides_without_request_enablement() {
        let active = controls(true, false);
        assert_eq!(decide(&active, false, "allow").unwrap().action, "block");
        assert_eq!(decide(&active, true, "review").unwrap().action, "allow");
        let inactive = controls(false, false);
        assert_eq!(decide(&inactive, false, "allow"), None);
        assert_eq!(decide(&inactive, true, "review"), None);
    }

    #[test]
    fn disabled_permission_and_quarantine_are_mcp_floors() {
        assert_eq!(
            decide(&controls(true, true), false, "review")
                .unwrap()
                .action,
            "block"
        );
        let mut active = controls(true, false);
        active
            .set_security_quarantine(false, &BTreeSet::from(["command.mcp-enola".into()]))
            .unwrap();
        assert_eq!(decide(&active, true, "review").unwrap().action, "block");
        active
            .set_security_quarantine(true, &BTreeSet::new())
            .unwrap();
        assert_eq!(decide(&active, true, "review").unwrap().action, "block");
        assert_eq!(
            active
                .decide_contributed_mcp(&ContributedMcpInput {
                    current_action: "allow",
                    server_identity: None,
                    artifact_transport: None,
                    server_name: None,
                    tool_name: None,
                    layers: &[],
                })
                .unwrap()
                .action,
            "block"
        );
        let mut locked = controls(true, false);
        locked.global_block = true;
        assert_eq!(decide(&locked, true, "review").unwrap().action, "block");
    }
}
