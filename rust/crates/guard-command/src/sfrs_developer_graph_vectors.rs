//! Replay of the recorded compound developer effect graph cases.

use std::path::Path;

use serde_json::{json, Value};

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::github_capability_contract::{
    github_assessment, GitHubCommandAssessment, GitHubCommandCapability,
};
use crate::sfrs_developer_graph::{compound_developer_effect_graph, GraphInputs};

struct Host;

impl InspectionHost for Host {
    fn env(&self, _name: &str) -> Option<String> {
        None
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
}

/// Mirrors the recorder stand-in for the native GitHub CLI classifier.
pub(crate) fn stand_in(args: &[String]) -> GitHubCommandAssessment {
    let joined = args.join(" ");
    let capability = if joined.starts_with("pr merge") {
        GitHubCommandCapability::MergeRemote
    } else if joined.contains("delete") {
        GitHubCommandCapability::DeleteRemote
    } else if joined.starts_with("pr view") || joined.starts_with("repo view") {
        GitHubCommandCapability::ReadRemote
    } else {
        GitHubCommandCapability::Unknown
    };
    github_assessment(&[capability], &format!("stub.{joined}"), "stub")
}

fn effect_name(effect: crate::sfrs_developer_graph::DeveloperShellEffect) -> &'static str {
    use crate::sfrs_developer_graph::DeveloperShellEffect as E;
    match effect {
        E::Directory => "directory",
        E::LocalRead => "local-read",
        E::RemoteRead => "remote-read",
        E::StreamFilter => "stream-filter",
        E::StaticOutput => "static-output",
        E::SyntaxCheck => "syntax-check",
    }
}

pub(crate) fn run(args: &[Value]) -> Value {
    let text = args[0].as_str().expect("text");
    let cwd = args[1].as_str().map(Path::new);
    let home = Path::new(args[2].as_str().expect("home"));
    let host = Host;
    let ctx = Ctx::new(&host, "/", &home.to_string_lossy());
    let inputs = GraphInputs {
        cwd,
        home_dir: home,
        ctx: &ctx,
        managed_bin_dirs: &[],
        classify_github: stand_in,
    };
    match compound_developer_effect_graph(text, &inputs) {
        None => Value::Null,
        Some(graph) => json!({
            "complete": graph.context.complete,
            "segments": graph.context.segments.len(),
            "effects": graph.segments.iter().map(|item| json!([item.index, item.command_name, effect_name(item.effect)])).collect::<Vec<_>>(),
            "workspace_root": graph.context.workspace_root.as_ref().map(|path| path.to_string_lossy().into_owned()),
        }),
    }
}
