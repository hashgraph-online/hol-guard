//! Freshness binding carried by a policy push for the direct resident hook lane.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DIRECT_LANE_MAX_WORKSPACES: usize = 512;
pub const DIRECT_LANE_MAX_HARNESS_POSTURES: usize = 32;
pub const DIRECT_LANE_HARNESS_POSTURES: &[&str] = &["protected", "extra_careful", "watch"];
pub const DIRECT_LANE_MAX_INPUTS: usize = 256;
pub const DIRECT_LANE_MAX_PATH_BYTES: usize = 4096;
pub const DIRECT_LANE_MAX_SINK_ARGS: usize = 8;
pub const DIRECT_LANE_MAX_SINK_ARG_BYTES: usize = 16_384;

/// Publisher-observed state that a pushed snapshot was compiled against.
///
/// `workspaces` are the workspace roots whose overlays the snapshot settled.
/// `inputs` are the non-database policy files the publisher watched, each
/// with the stat identity observed before compilation, or `None` when the
/// file was absent. The resident re-observes the inputs before using the
/// snapshot without the daemon.
///
/// The remaining fields carry daemon state that the snapshot itself does not:
/// the daemon's home directory, the per-harness posture overrides it binds to
/// the same ACK, and whether any custom command-line block rule existed when
/// the snapshot was compiled. A direct hook defers whenever one is absent.
/// `evidence_drain` says the daemon drains the evidence of direct answers;
/// without it the resident answers nothing directly.
/// `contained_sink_command` is the argv prefix that starts the daemon's
/// Guard CLI, which the daemon puts in front of a contained execution
/// rewrite; without it such a rewrite stays with the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneBindingV1 {
    pub workspaces: Vec<String>,
    pub inputs: Vec<DirectLaneInputV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_postures: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cli_block_rules: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_drain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contained_sink_command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneInputV1 {
    pub path: String,
    pub stat: Option<DirectLaneStatV1>,
}

/// The `(mtime_ns, size, ino, ctime_ns)` identity of a followed `stat`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectLaneStatV1 {
    pub mtime_ns: i64,
    pub size: u64,
    pub ino: u64,
    pub ctime_ns: i64,
}

impl DirectLaneBindingV1 {
    pub fn is_valid(&self) -> bool {
        if self.workspaces.len() > DIRECT_LANE_MAX_WORKSPACES
            || self.inputs.len() > DIRECT_LANE_MAX_INPUTS
        {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        for workspace in &self.workspaces {
            if !direct_lane_path_valid(workspace) || !seen.insert(workspace.as_str()) {
                return false;
            }
        }
        seen.clear();
        for input in &self.inputs {
            if !direct_lane_path_valid(&input.path) || !seen.insert(input.path.as_str()) {
                return false;
            }
        }
        if self
            .home_dir
            .as_deref()
            .is_some_and(|home_dir| !direct_lane_path_valid(home_dir))
        {
            return false;
        }
        if let Some(postures) = &self.harness_postures {
            if postures.len() > DIRECT_LANE_MAX_HARNESS_POSTURES
                || postures.iter().any(|(harness, posture)| {
                    harness.is_empty()
                        || harness.len() > 64
                        || !DIRECT_LANE_HARNESS_POSTURES.contains(&posture.as_str())
                })
            {
                return false;
            }
        }
        if let Some(command) = &self.contained_sink_command {
            if command.is_empty()
                || command.len() > DIRECT_LANE_MAX_SINK_ARGS
                || !direct_lane_path_valid(&command[0])
                || command.iter().any(|argument| {
                    argument.is_empty()
                        || argument.len() > DIRECT_LANE_MAX_SINK_ARG_BYTES
                        || argument.contains('\0')
                })
            {
                return false;
            }
        }
        true
    }
}

fn direct_lane_path_valid(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= DIRECT_LANE_MAX_PATH_BYTES
        && !path.contains('\0')
        && std::path::Path::new(path).is_absolute()
}
