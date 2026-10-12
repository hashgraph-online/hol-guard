//! Replay entry points for the request-classification parity vectors.
//!
//! The conformance harness hands each recorded call to [`replay_entry`], which
//! decodes the recorded arguments, runs the classifier and encodes the result
//! with the same type tags the vectors carry.

#![doc(hidden)]

use std::path::{Path, PathBuf};

use guard_contracts::CompoundGitSegmentV1;
use serde_json::{json, Map, Value};

use crate::benign_request_api::ovalue_from_json;
use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::hook_adapter_value::OValue;
use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;
use crate::sfrs_requests::{
    build_file_read_request_artifact, build_file_write_request_artifact, classify_sensitive_path,
    command_list_candidate_texts, extract_sensitive_file_read_request,
    extract_sensitive_file_read_request_from_action, extract_sensitive_file_write_request,
    FileReadRequest, FileWriteRequest, SensitivePath,
};

/// Whether the classifier has an implementation for `entry`.
#[must_use]
pub fn implements(entry: &str) -> bool {
    crate::sfrs_replay_context::ENTRIES.contains(&entry)
        || matches!(
            entry,
            "classify_sensitive_path"
                | "command_list_candidate_texts"
                | "extract_sensitive_file_read_request"
                | "extract_sensitive_file_read_request_from_action"
                | "extract_sensitive_file_write_request"
                | "build_file_read_request_artifact"
                | "build_file_write_request_artifact"
                | "is_explicitly_benign_native_file_read_request"
                | "is_explicitly_benign_tool_action_request"
                | "read_only_lookup_target_is_safe"
        )
}

/// Run the classifier for `entry` over one recorded call.
///
/// `env` is the recorded environment and `dir` the materialized test
/// directory used as the working directory.
///
/// # Errors
///
/// Returns a description when the recorded arguments do not decode or the
/// entry has no implementation yet.
pub fn replay_entry(
    entry: &str,
    args: &Value,
    _evaluation: &Value,
    env: &Value,
    dir: &Path,
) -> Result<Value, String> {
    match entry {
        "classify_sensitive_path" => {
            let found = classify_sensitive_path(
                str_arg(args, "path").unwrap_or_default(),
                path_arg(args, "cwd").as_deref(),
                path_arg(args, "home_dir").as_deref(),
            );
            Ok(found.map_or(Value::Null, |found| encode_sensitive_path(&found)))
        }
        "command_list_candidate_texts" => {
            let values = list_arg(args, "values")?;
            let preserve = args["preserve_items"].as_bool().unwrap_or(false);
            Ok(json!(command_list_candidate_texts(&values, preserve)))
        }
        "extract_sensitive_file_read_request" => {
            let found = extract_sensitive_file_read_request(
                &ovalue_arg(args, "tool_name"),
                &ovalue_arg(args, "arguments"),
                path_arg(args, "cwd").as_deref(),
                path_arg(args, "home_dir").as_deref(),
            );
            Ok(found.map_or(Value::Null, |found| encode_read_request(&found)))
        }
        "extract_sensitive_file_read_request_from_action" => {
            let action = ovalue_arg(args, "action");
            let found = action.as_map().and_then(|action| {
                extract_sensitive_file_read_request_from_action(
                    action,
                    path_arg(args, "cwd").as_deref(),
                    path_arg(args, "home_dir").as_deref(),
                )
            });
            Ok(found.map_or(Value::Null, |found| encode_read_request(&found)))
        }
        "extract_sensitive_file_write_request" => {
            let protected = protected_paths(&args["protected_paths"]);
            let found = extract_sensitive_file_write_request(
                &ovalue_arg(args, "tool_name"),
                &ovalue_arg(args, "arguments"),
                path_arg(args, "cwd").as_deref(),
                path_arg(args, "home_dir").as_deref(),
                &protected,
            );
            Ok(found.map_or(Value::Null, |found| encode_write_request(&found)))
        }
        "build_file_read_request_artifact" => {
            let request = decode_read_request(&args["request"])?;
            Ok(artifact_wire(build_file_read_request_artifact(
                str_arg(args, "harness").unwrap_or_default(),
                &request,
                str_arg(args, "config_path").unwrap_or_default(),
                str_arg(args, "source_scope").unwrap_or_default(),
            )))
        }
        "build_file_write_request_artifact" => {
            let request = decode_write_request(&args["request"])?;
            Ok(artifact_wire(build_file_write_request_artifact(
                str_arg(args, "harness").unwrap_or_default(),
                &request,
                str_arg(args, "config_path").unwrap_or_default(),
                str_arg(args, "source_scope").unwrap_or_default(),
            )))
        }
        "is_explicitly_benign_native_file_read_request" => {
            // Never read the reviewer's machine: the call runs in its own
            // materialized directory with the recorded HOME.
            let process_cwd = dir.to_string_lossy().into_owned();
            let home = env
                .get("HOME")
                .and_then(Value::as_str)
                .map_or_else(|| process_cwd.clone(), str::to_owned);
            let host = ReplayHost::new(&home);
            let ctx = Ctx::new(&host, &process_cwd, &home);
            // The public entry point the resident composes with, so the
            // recorded Python vectors prove the exact production path.
            let null = Value::Null;
            Ok(json!(
                crate::benign_request_api::is_benign_native_file_read(
                    args.get("tool_name").unwrap_or(&null),
                    args.get("arguments").unwrap_or(&null),
                    path_arg(args, "cwd").as_deref(),
                    path_arg(args, "home_dir").as_deref(),
                    &ctx,
                )
            ))
        }
        "is_explicitly_benign_tool_action_request" => {
            let process_cwd = dir.to_string_lossy().into_owned();
            let home = env
                .get("HOME")
                .and_then(Value::as_str)
                .map_or_else(|| process_cwd.clone(), str::to_owned);
            let host = ReplayHost::new(&home)
                .with_recorded_env(env.as_object().unwrap_or(&serde_json::Map::new()));
            let ctx = Ctx::new(&host, &process_cwd, &home);
            let null = Value::Null;
            // No control snapshot: the vectors were recorded without one.
            let benign = crate::benign_request_api::is_benign_tool_action(
                args.get("tool_name").unwrap_or(&null),
                args.get("arguments").unwrap_or(&null),
                path_arg(args, "cwd").as_deref(),
                path_arg(args, "home_dir").as_deref(),
                &ctx,
                None,
            );
            if !benign && host.resident_requested.get() {
                return Ok(json!({ RESIDENT_HOST_REQUIRED: true }));
            }
            Ok(json!(benign))
        }
        "read_only_lookup_target_is_safe" => Ok(json!(read_only_lookup_target_is_safe(
            str_arg(args, "target").unwrap_or_default(),
            args["allow_dirs"].as_bool().unwrap_or(false),
            path_arg(args, "home_dir").as_deref(),
        ))),
        other => {
            let process_cwd = dir.to_string_lossy().into_owned();
            let home = env
                .get("HOME")
                .and_then(Value::as_str)
                .map_or_else(|| process_cwd.clone(), str::to_owned);
            let host = ReplayHost::new(&home);
            let ctx = Ctx::new(&host, &process_cwd, &home);
            let result = crate::sfrs_replay_context::replay(other, args, &ctx, Path::new(&home))
                .unwrap_or_else(|| Err(format!("entry {other} is not implemented")))?;
            if result.is_null() && host.resident_requested.get() {
                return Ok(json!({ RESIDENT_HOST_REQUIRED: true }));
            }
            Ok(result)
        }
    }
}

/// Host for classifiers that never run a process.
struct ReplayHost {
    home: String,
    /// Recorded variables besides `HOME` (`PATH`, `RIPGREP_CONFIG_PATH`).
    extra_env: Vec<(String, String)>,
    resident_requested: std::cell::Cell<bool>,
}

impl ReplayHost {
    fn with_recorded_env(mut self, env: &serde_json::Map<String, Value>) -> Self {
        self.extra_env = env
            .iter()
            .filter(|(key, _)| matches!(key.as_str(), "PATH" | "RIPGREP_CONFIG_PATH"))
            .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
            .collect();
        self
    }

    fn new(home: &str) -> Self {
        Self {
            home: home.to_owned(),
            extra_env: Vec::new(),
            resident_requested: std::cell::Cell::new(false),
        }
    }
}

/// Marker for a call that needed a resident service and failed closed.
///
/// Replay never runs git or asks the resident for path trust, so the harness
/// counts these vectors as deferred to the resident host instead of comparing
/// them.
pub const RESIDENT_HOST_REQUIRED: &str = "resident_host_required";

impl InspectionHost for ReplayHost {
    fn env(&self, name: &str) -> Option<String> {
        if name == "HOME" {
            return Some(self.home.clone());
        }
        self.extra_env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
    fn git_executable(&self) -> Option<String> {
        self.resident_requested.set(true);
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        self.resident_requested.set(true);
        GitRun::Failed("replay host does not run git")
    }
    fn compound_git_chain(&self, _: &[CompoundGitSegmentV1], _: bool) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn git_inspection_segment(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn cached_diff_pathspecs(&self, _: &[String]) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn git_show_config(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn standalone_git_routine(&self, _: &[CompoundGitSegmentV1], _: bool, _: Option<&str>) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn trusted_path_command(&self, _: &str, _: &str, _: &str) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn bun_script_evidence_complete(&self, _: &[String], _: &str) -> bool {
        self.resident_requested.set(true);
        false
    }
    fn direct_tool_authority(&self) -> Option<&dyn crate::direct_vitest::DirectToolAuthority> {
        self.resident_requested.set(true);
        None
    }
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn path_arg(args: &Value, key: &str) -> Option<PathBuf> {
    str_arg(args, key).map(|text| Path::new(text).to_path_buf())
}

fn ovalue_arg(args: &Value, key: &str) -> OValue {
    args.get(key).map_or(OValue::Null, ovalue_from_json)
}

fn list_arg(args: &Value, key: &str) -> Result<Vec<OValue>, String> {
    match ovalue_arg(args, key) {
        OValue::List(items) => Ok(items),
        _ => Err(format!("argument {key} is not a list")),
    }
}

fn protected_paths(value: &Value) -> Vec<(String, String)> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(path, label)| Some((path.clone(), label.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn decode_sensitive_path(value: &Value) -> SensitivePath {
    SensitivePath {
        family: text(value, "family"),
        path: text(value, "path"),
        sensitivity: text(value, "sensitivity"),
        reason: text(value, "reason"),
        requested_path: text(value, "requested_path"),
    }
}

fn decode_read_request(value: &Value) -> Result<FileReadRequest, String> {
    if value.get("$type").and_then(Value::as_str) != Some("FileReadRequestMatch") {
        return Err("request is not a FileReadRequestMatch".to_owned());
    }
    Ok(FileReadRequest {
        tool_name: text(value, "tool_name"),
        normalized_tool_name: text(value, "normalized_tool_name"),
        path_match: decode_sensitive_path(&value["path_match"]),
    })
}

fn decode_write_request(value: &Value) -> Result<FileWriteRequest, String> {
    if value.get("$type").and_then(Value::as_str) != Some("FileWriteRequestMatch") {
        return Err("request is not a FileWriteRequestMatch".to_owned());
    }
    Ok(FileWriteRequest {
        tool_name: text(value, "tool_name"),
        normalized_tool_name: text(value, "normalized_tool_name"),
        normalized_path: text(value, "normalized_path"),
        path_class: text(value, "path_class"),
        reason: text(value, "reason"),
        action_class: text(value, "action_class"),
    })
}

fn encode_sensitive_path(found: &SensitivePath) -> Value {
    json!({
        "$type": "SecretPathMatch",
        "family": found.family,
        "path": found.path,
        "reason": found.reason,
        "requested_path": found.requested_path,
        "sensitivity": found.sensitivity,
    })
}

fn encode_read_request(found: &FileReadRequest) -> Value {
    json!({
        "$type": "FileReadRequestMatch",
        "normalized_tool_name": found.normalized_tool_name,
        "path_match": encode_sensitive_path(&found.path_match),
        "tool_name": found.tool_name,
    })
}

fn encode_write_request(found: &FileWriteRequest) -> Value {
    json!({
        "$type": "FileWriteRequestMatch",
        "action_class": found.action_class,
        "normalized_path": found.normalized_path,
        "normalized_tool_name": found.normalized_tool_name,
        "path_class": found.path_class,
        "reason": found.reason,
        "tool_name": found.tool_name,
    })
}

fn artifact_wire(artifact: Value) -> Value {
    let mut tagged = Map::new();
    tagged.insert("$type".to_owned(), json!("GuardArtifact"));
    if let Value::Object(fields) = artifact {
        tagged.extend(fields);
    }
    Value::Object(tagged)
}
