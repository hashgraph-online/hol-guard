use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use guard_command::bash_approval::graph::Graph;
use guard_contained_process::bound_fs::Directory;

use super::{text, CapturedReport, Resolver, Result};

pub(super) fn capture(
    graph: &Graph,
    resolver: &Resolver<'_>,
    cwd: &Path,
    guard_home: &Path,
    bind_outputs: bool,
) -> Result<(BTreeMap<String, String>, Option<CapturedReport>)> {
    let mut outputs = BTreeMap::new();
    let mut report = None;
    for effect in &graph.writes {
        resolver.check()?;
        let leaf = effect.redirect.path.rsplit('/').next().unwrap_or("");
        if matches!(leaf, "" | "." | "..") {
            return Err("bash_output_path_invalid");
        }
        if guard_command::bash_approval::is_descriptor_reference(&effect.redirect.path) {
            return Err("bash_process_descriptor_unproven");
        }
        if outputs.contains_key(&effect.redirect.path) {
            continue;
        }
        let path = cwd.join(&effect.redirect.path);
        let parent = std::fs::canonicalize(path.parent().ok_or("bash_output_path_invalid")?)
            .map_err(|_| "bash_output_parent_unavailable")?;
        if guard_command::bash_approval::is_descriptor_reference(&text(&parent)?) {
            return Err("bash_process_descriptor_unproven");
        }
        let resolved = parent.join(path.file_name().ok_or("bash_output_path_invalid")?);
        // Guard state is never an overridable report destination, including
        // when an otherwise ordinary path aliases its configured home.
        if resolved.starts_with(guard_home) {
            return Err("bash_output_guard_state_protected");
        }
        if guard_command::bash_approval::is_descriptor_reference(&text(&resolved)?) {
            return Err("bash_process_descriptor_unproven");
        }
        let directory = Directory::open(&parent).map_err(|_| "bash_output_parent_unavailable")?;
        guard_contained_process::bound_output::validate_target(
            &directory,
            resolved.file_name().ok_or("bash_output_path_invalid")?,
        )
        .map_err(|_| "bash_output_target_unavailable")?;
        if bind_outputs {
            report = Some(CapturedReport {
                directory: Arc::new(directory),
                leaf: resolved
                    .file_name()
                    .ok_or("bash_output_path_invalid")?
                    .to_os_string(),
                append: graph
                    .initial_output()
                    .ok_or("bash_output_timing_unproven")?
                    .append,
            });
        }
        outputs.insert(effect.redirect.path.clone(), text(&resolved)?);
    }
    Ok((outputs, report))
}
