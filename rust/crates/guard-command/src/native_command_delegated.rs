//! Tightening-only native control gates for delegated package and MCP surfaces.
//! These gates do not replace advisory scans or approve an unknown invocation.

use super::*;
use guard_contracts::{NativeCommandPermissionObservationV1, NativeMatcherEvidenceV1};

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

fn inspection_only(arguments: &[String]) -> bool {
    matches!(arguments, [only] if matches!(only.as_str(), "--version" | "--help" | "-h"))
}

pub(crate) fn normalized_tool(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}

impl CompiledNativeCommandControls {
    pub(super) fn delegated_observations(
        &self,
        command: Option<&CanonicalCommandV1>,
        tool: Option<&str>,
        packages: &[String],
        batch: &mut NativeCommandObservationBatchV1,
        deadline: Option<Instant>,
    ) -> Result<&'static str, &'static str> {
        let mut floor = "allow";
        for extension in &self.program.extensions {
            if deadline.is_some_and(|limit| Instant::now() >= limit) {
                return Err("native_command_deadline_exceeded");
            }
            if !self.active_extensions.contains(&extension.extension_id) {
                continue;
            }
            if extension.delegated_protection.as_deref() == Some("package-firewall") {
                let Some(command) = command else { continue };
                let evidence: Vec<_> = command
                    .segments
                    .iter()
                    .enumerate()
                    .filter_map(|(index, segment)| {
                        let executable = basename(segment.executable.as_deref()?);
                        if !extension
                            .executables
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(executable))
                            || inspection_only(&segment.arguments)
                        {
                            return None;
                        }
                        Some(NativeMatcherEvidenceV1 {
                            segment_index: index,
                            // Use the catalog basename, never an input path.
                            executable: extension
                                .executables
                                .iter()
                                .find(|value| value.eq_ignore_ascii_case(executable))
                                .cloned(),
                            detail: "Matched bounded structured command constraints.".into(),
                        })
                    })
                    .collect();
                if evidence.is_empty() {
                    continue;
                }
                for permission in &extension.permissions {
                    if batch.observations.len() + batch.permission_observations.len()
                        >= guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
                    {
                        return Err("native_command_evidence_limit_exceeded");
                    }
                    batch
                        .permission_observations
                        .push(NativeCommandPermissionObservationV1 {
                            mcp_tool: None,
                            extension_id: extension.extension_id.clone(),
                            permission_id: permission.permission_id.clone(),
                            matcher_evidence: evidence.clone(),
                            uncertainty_reasons: Vec::new(),
                        });
                }
            }
            if let (Some(mcp), Some(tool)) = (&extension.mcp, tool) {
                // A package identity or exact conventional server namespace can
                // select a stronger floor, but never supplies allow authority.
                let alias = extension
                    .extension_id
                    .strip_prefix("command.mcp-")
                    .unwrap_or("");
                let prefix = format!("mcp__{alias}__");
                let lower = tool.to_ascii_lowercase();
                let named = lower.strip_prefix(&prefix);
                let package_match = mcp.mcp_launch.package.as_deref().is_some_and(|expected| {
                    packages
                        .iter()
                        .any(|package| package.eq_ignore_ascii_case(expected))
                });
                let remote_named = mcp.mcp_launch.kind == "remote-http"
                    && mcp.mcp_launch.server_names.iter().any(|server| {
                        let prefix = format!("mcp__{}__", server.to_ascii_lowercase());
                        lower.starts_with(&prefix)
                    });
                if named.is_none() && !package_match && !remote_named {
                    continue;
                }
                let name = named.unwrap_or_else(|| lower.rsplit("__").next().unwrap_or(&lower));
                let wanted = normalized_tool(name);
                let selected = mcp
                    .mcp_tools
                    .iter()
                    .find(|entry| normalized_tool(&entry.name) == wanted)
                    .or_else(|| mcp.mcp_tools.iter().find(|entry| entry.name == "other"));
                let Some(selected) = selected else {
                    continue;
                };
                floor = match selected.state.as_str() {
                    "block" => "block",
                    "review" if floor != "block" => "review",
                    _ => floor,
                };
                for permission in &extension.permissions {
                    if batch.observations.len() + batch.permission_observations.len()
                        >= guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
                    {
                        return Err("native_command_evidence_limit_exceeded");
                    }
                    batch
                        .permission_observations
                        .push(NativeCommandPermissionObservationV1 {
                            // No synthetic shell segment is invented for a tool call.
                            mcp_tool: Some(selected.name.clone()),
                            extension_id: extension.extension_id.clone(),
                            permission_id: permission.permission_id.clone(),
                            matcher_evidence: Vec::new(),
                            uncertainty_reasons: Vec::new(),
                        });
                }
            }
        }
        let count = batch.observations.len() + batch.permission_observations.len();
        let evidence = batch
            .permission_observations
            .iter()
            .map(|item| item.matcher_evidence.len())
            .sum::<usize>()
            + batch
                .observations
                .iter()
                .map(|item| {
                    item.matcher_evidence.len()
                        + item
                            .safe_variants
                            .iter()
                            .map(|safe| safe.matcher_evidence.len())
                            .sum::<usize>()
                })
                .sum::<usize>();
        if count > guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
            || evidence > guard_contracts::MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
        {
            return Err("native_command_evidence_limit_exceeded");
        }
        Ok(floor)
    }
}
