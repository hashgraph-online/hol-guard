//! Tightening-only native control gates for delegated package and MCP surfaces.
//! These gates do not replace advisory scans or approve an unknown invocation.

use super::*;
use guard_contracts::{NativeCommandPermissionObservationV1, NativeMatcherEvidenceV1};

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

/// The managers that read a lone `-V` as something other than "print the
/// version and exit". Gradle and Maven both spell `--show-version` that way,
/// which prints the version and then runs the build: the default tasks or the
/// pom's own default goal execute, and resolving them reaches a registry.
/// Bundler reads it as `--verbose`, and a bare `bundle` installs, so
/// `bundle -V` fetches gems. Each of those is work the firewall is here to
/// observe, so for them the flag is not an inspection.
const VERBOSE_SHORT_V: &[&str] = &["mvn", "mvnw", "gradle", "gradlew", "bundle", "bundler"];

/// The managers that read a single-dash word as a whole option name before
/// they read it as a cluster of short flags, so `-version` is the same probe
/// as `--version`: Maven parses its command line with Commons CLI, and
/// Gradle's own parser looks the whole token up among its registered names
/// first. Both print the version and exit. Everywhere else that word is a
/// cluster -- npm reads `-version` as `-v -e -r -s -i -o -n`, and Bundler's
/// option parser reads it the same way -- so there it is no inspection.
const SINGLE_DASH_LONG_VERSION: &[&str] = &[
    "mvn",
    "mvnw",
    "mvn.cmd",
    "mvnw.cmd",
    "gradle",
    "gradlew",
    "gradle.bat",
    "gradlew.bat",
];

/// A lone inspection flag is the whole argument list, so it names no package
/// and no subcommand: the manager prints its version or its usage and exits.
/// `-v` is the short spelling of that everywhere here, and the one agents
/// reach for first. `-V` is the same probe for most of them, and for the
/// managers in [`VERBOSE_SHORT_V`] it is not a probe at all. `-version` is
/// the spelling the JVM build tools document, and a probe only for the
/// managers in [`SINGLE_DASH_LONG_VERSION`].
fn inspection_only(executable: &str, arguments: &[String]) -> bool {
    let [only] = arguments else { return false };
    match only.as_str() {
        "--version" | "--help" | "-h" | "-v" => true,
        "-V" => !VERBOSE_SHORT_V
            .iter()
            .any(|name| name.eq_ignore_ascii_case(executable)),
        "-version" => SINGLE_DASH_LONG_VERSION
            .iter()
            .any(|name| name.eq_ignore_ascii_case(executable)),
        _ => false,
    }
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
        for &index in self.candidate_index.extension_indices() {
            let extension = &self.program.extensions[index];
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
                            || inspection_only(executable, &segment.arguments)
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

#[cfg(test)]
mod tests {
    use super::inspection_only;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_jvm_build_tools_read_a_single_dash_long_version_as_a_probe() {
        for executable in ["mvn", "mvnw", "MVN.CMD", "gradle", "gradlew", "gradlew.bat"] {
            assert!(
                inspection_only(executable, &arguments(&["-version"])),
                "{executable} -version"
            );
        }
    }

    #[test]
    fn a_single_dash_long_version_is_a_cluster_elsewhere_and_never_a_lone_word() {
        for (executable, words) in [
            // npm reads it as `-v -e -r -s -i -o -n`, and Bundler's option
            // parser splits it the same way, so neither prints a version.
            ("npm", vec!["-version"]),
            ("bundle", vec!["-version"]),
            ("yarn", vec!["-version"]),
            // A build still runs beside the flag, whichever way it is read.
            ("gradle", vec!["-version", "build"]),
            ("mvn", vec!["-version", "-q"]),
            ("mvn", vec!["-q", "-version"]),
        ] {
            assert!(
                !inspection_only(executable, &arguments(&words)),
                "{executable} {words:?}"
            );
        }
    }

    #[test]
    fn the_short_spellings_keep_the_readings_they_had() {
        assert!(inspection_only("mvn", &arguments(&["-v"])));
        assert!(inspection_only("mvn", &arguments(&["--version"])));
        // `-V` is `--show-version` for Maven and Gradle: the build runs.
        assert!(!inspection_only("mvn", &arguments(&["-V"])));
        assert!(!inspection_only("gradle", &arguments(&["-V"])));
        assert!(inspection_only("npm", &arguments(&["-V"])));
    }
}
