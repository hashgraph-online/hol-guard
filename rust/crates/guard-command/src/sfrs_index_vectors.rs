//! Replay of the recorded staged-index Git inspection cases.

use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::sfrs_developer_graph::GraphInputs;
use crate::sfrs_git_cached_diff::{
    cached_diff_kind, cached_diff_operands_are_safe, command_has_execution_routed_git_cached_diff,
    command_has_owned_git_cached_diff, executable_tokens, git_diff_operands,
    has_unproven_repository_selector, proof_cached_diff_tokens, CachedDiffKind,
};
use crate::sfrs_git_index::{
    index_scan_rg_args_are_safe, is_low_risk_git_index_inspection,
    owned_git_index_inspection_action_class,
};
use crate::sfrs_source_edit_context::low_risk_developer_execution_context;
use guard_contracts::CompoundGitSegmentV1;

/// Mirrors the recorder stand-ins for the resident git services.
struct Host {
    ripgrep_config: bool,
}

impl InspectionHost for Host {
    fn env(&self, name: &str) -> Option<String> {
        (self.ripgrep_config && name == "RIPGREP_CONFIG_PATH").then(|| "x".to_owned())
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        !values.is_empty()
            && values
                .iter()
                .all(|value| !value.is_empty() && !value.starts_with('-') && !value.contains("bad"))
    }
    fn git_inspection_segment(&self, segment: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        !segment
            .tokens
            .iter()
            .any(|token| token.contains("unsafe-seg"))
    }
    fn git_show_config(&self, _: &CompoundGitSegmentV1, repository_path: Option<&str>) -> bool {
        repository_path.is_none_or(|path| !path.contains("unsafe-repo"))
    }
    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        _: bool,
        _: Option<&str>,
    ) -> bool {
        segments
            .iter()
            .flat_map(|segment| &segment.tokens)
            .any(|token| token.contains("standalone-ok"))
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

fn list(items: Vec<String>) -> Value {
    Value::from(items)
}

pub(crate) fn run(function: &str, args: &[Value]) -> Option<Value> {
    let plain = Host {
        ripgrep_config: false,
    };
    let ctx = Ctx::new(&plain, "/", "/");
    Some(match function {
        "git_index_cached_diff_kind" => match cached_diff_kind(&strings(&args[0])) {
            None => Value::Null,
            Some(CachedDiffKind::Owned) => "owned".into(),
            Some(CachedDiffKind::Routed) => "routed".into(),
        },
        "git_index_diff_operands" => {
            git_diff_operands(&strings(&args[0])).map_or(Value::Null, list)
        }
        "git_index_executable_tokens" => {
            executable_tokens(&strings(&args[0])).map_or(Value::Null, list)
        }
        "git_index_unproven_selector" => {
            has_unproven_repository_selector(&strings(&args[0])).into()
        }
        "git_index_proof_tokens" => list(proof_cached_diff_tokens(&strings(&args[0]))),
        "git_index_chain_owned" | "git_index_chain_routed" => {
            let chain: Vec<Vec<String>> = args[0]
                .as_array()
                .expect("chain")
                .iter()
                .map(strings)
                .collect();
            if function.ends_with("owned") {
                command_has_owned_git_cached_diff(&chain).into()
            } else {
                command_has_execution_routed_git_cached_diff(&chain).into()
            }
        }
        "git_index_operands_safe" => cached_diff_operands_are_safe(&strings(&args[0]), &ctx).into(),
        "git_index_rg_args" => {
            let host = Host {
                ripgrep_config: args[1].as_bool().expect("flag"),
            };
            let ctx = Ctx::new(&host, "/", "/");
            index_scan_rg_args_are_safe(&strings(&args[0]), &ctx).into()
        }
        "git_index_is_low_risk" | "git_index_action_class" => {
            let text = args[0].as_str().expect("text");
            let cwd = args[1].as_str().map(Path::new);
            let home = Path::new(args[2].as_str().expect("home"));
            if function == "git_index_is_low_risk" {
                is_low_risk_git_index_inspection(text, cwd, Some(home), &ctx).into()
            } else {
                owned_git_index_inspection_action_class(text, cwd, Some(home), &ctx)
                    .map_or(Value::Null, Value::from)
            }
        }
        "low_risk_developer_context" => {
            let text = args[0].as_str().expect("text");
            let home = Path::new(args[2].as_str().expect("home"));
            let ctx = Ctx::new(&plain, "/", &home.to_string_lossy());
            let inputs = GraphInputs {
                cwd: args[1].as_str().map(Path::new),
                home_dir: home,
                ctx: &ctx,
                managed_bin_dirs: &[],
                classify_github: crate::sfrs_developer_graph_vectors::stand_in,
            };
            match low_risk_developer_execution_context(text, &inputs) {
                None => Value::Null,
                Some(context) => serde_json::json!({
                    "complete": context.complete,
                    "segments": context.segments.len(),
                    "command_text": context.command_text,
                    "workspace_root": context
                        .workspace_root
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned()),
                }),
            }
        }
        _ => return None,
    })
}
