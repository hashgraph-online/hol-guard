//! Project tools started through a package runner.
//!
//! `npx <tool>`, `bunx <tool>` and `bun x <tool>` run the project's own
//! `node_modules/.bin/<tool>` when it is installed there, exactly as
//! `./node_modules/.bin/<tool>` would, and fetch from the registry only when
//! it is not. A runner whose tool is installed where it runs is local work the
//! sandbox bounds; one that could fetch keeps its package review.
use crate::package_intent_common::PackageIntent;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;

/// Runner options that neither name a package nor allow a fetch.
const RUNNER_OPTIONS: &[&str] = &["--no-install", "--bun"];

/// The arguments after the runner itself, when `segment` is one.
pub(super) fn runner_arguments(segment: &CommandSegmentV1) -> Option<&[String]> {
    match segment.executable.as_deref()? {
        "npx" | "bunx" => Some(&segment.arguments),
        "bun" => match segment.arguments.split_first() {
            Some((verb, rest)) if verb == "x" => Some(rest),
            _ => None,
        },
        _ => None,
    }
}

/// The tools the runners in `model` start, each a bare name installed in
/// `node_modules/.bin` of the directory it runs in. `None` when there is no
/// runner, or any runner names a version or source, takes an unknown option,
/// or runs where the leading `cd` steps cannot be followed. The caller's shape
/// check still proves every `cd` stays inside `workspace`.
pub(super) fn installed_tools(model: &CanonicalCommandV1, workspace: &Path) -> Option<Vec<String>> {
    let mut directory = workspace.to_path_buf();
    let mut tools = Vec::new();
    for segment in &model.segments {
        let executable = segment.executable.as_deref()?;
        if matches!(executable, "cd" | "pushd" | "popd") {
            let [target] = segment.arguments.as_slice() else {
                return None;
            };
            if executable != "cd" || target.starts_with(['~', '-']) || target.contains('$') {
                return None;
            }
            directory = directory.join(target);
            continue;
        }
        let Some(arguments) = runner_arguments(segment) else {
            continue;
        };
        if !segment.environment_names.is_empty() || segment.path_overridden {
            return None;
        }
        let tool = arguments
            .iter()
            .find(|argument| !RUNNER_OPTIONS.contains(&argument.as_str()))?;
        let bare = !tool.starts_with(['.', '-'])
            && tool
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        let installed = directory.join("node_modules").join(".bin").join(tool);
        if !bare || !std::fs::metadata(&installed).is_ok_and(|metadata| metadata.is_file()) {
            return None;
        }
        tools.push(tool.clone());
    }
    (!tools.is_empty()).then_some(tools)
}

/// Whether the package intent parsed from the command is only these runners
/// starting their installed tools by name.
pub(super) fn intent_only_runs(intent: &PackageIntent, tools: &[String]) -> bool {
    intent.intent_kind == "execute"
        && !intent.targets.is_empty()
        && intent.targets.iter().all(|target| {
            target.source_url.is_none()
                && target
                    .requested_specifier
                    .as_deref()
                    .is_none_or(str::is_empty)
                && target.package_name.as_deref().is_some_and(|name| {
                    name == target.raw_spec && tools.iter().any(|tool| tool == name)
                })
        })
}
