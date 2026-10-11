//! Execution-owned containment for exact local Node, TypeScript and Bun runners.
//!
//! Faithful port of `contained_node_execution.py`,
//! `contained_typescript_execution.py` and
//! `contained_package_script_execution.py`. Every path fails closed: any
//! missing identity, drift or failed enforcement yields `None` so the caller
//! returns to Guard review instead of running uncontained.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::common::{canonical_workspace, clean_environment, file_sha256, framed_digest};
use super::contract::{Input, Policy, Request};
use super::decision::{execute_and_decide, ContainedOutcome, DecisionLabels, ExitPolicy};
use super::node_evidence::build_local_node_runner_evidence;
use super::script_evidence::build_local_package_script_evidence;
use super::snapshot::{complete_workspace_snapshot, reject_external_node_modules};
use super::ts_inputs::typescript_snapshot_inputs;

const SYSTEM_ROOTS: [&str; 6] = ["/System", "/usr", "/bin", "/lib", "/lib64", "/sbin"];
pub(crate) const DEFAULT_TIMEOUT_SECONDS: f64 = 120.0;

/// Caller-supplied launch context shared by the three runners.
pub(crate) struct Launch<'a> {
    pub(crate) workspace: &'a Path,
    pub(crate) manager: &'a str,
    pub(crate) argv: &'a [String],
    pub(crate) shim_directory: &'a Path,
    pub(crate) environment: &'a BTreeMap<String, String>,
    pub(crate) timeout_seconds: f64,
}

fn under_system_root(workspace: &Path) -> bool {
    SYSTEM_ROOTS.iter().any(|root| {
        let resolved = std::fs::canonicalize(root).unwrap_or_else(|_| PathBuf::from(root));
        workspace.starts_with(resolved)
    })
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file() && nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

/// Resolve `name` on `path_value` without ever selecting a Guard shim.
fn resolve_tool(name: &str, path_value: &str, shim_directory: &Path) -> Result<String, String> {
    let shim = std::fs::canonicalize(shim_directory).map_err(|error| error.to_string())?;
    let candidate = path_value
        .split(':')
        .filter(|entry| !entry.is_empty())
        .filter(|entry| super::pkg_json::weak_resolve(Path::new(entry)) != shim)
        .map(|entry| Path::new(entry).join(name))
        .find(|path| is_executable_file(path))
        .ok_or_else(|| format!("{name} executable unavailable"))?;
    let canonical = std::fs::canonicalize(candidate).map_err(|error| error.to_string())?;
    if canonical.starts_with(&shim) || !is_executable_file(&canonical) {
        return Err(format!("{name} executable is not path-pinned"));
    }
    String::from_utf8(canonical.as_os_str().as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn lowered(manager: &str) -> String {
    manager.trim().to_lowercase()
}

fn workspace_for(launch: &Launch) -> Result<PathBuf, String> {
    let canonical = canonical_workspace(launch.workspace)?;
    // The OS backends expose system runtime roots read-only; a project beneath
    // one of them would bypass omission through an absolute path.
    if under_system_root(&canonical) {
        return Err("workspace lies beneath a system root".to_owned());
    }
    Ok(canonical)
}

fn digests_of(inputs: &[Input]) -> HashMap<&str, String> {
    inputs
        .iter()
        .map(|item| {
            (
                item.snapshot_path.as_str(),
                format!("sha256:{}", item.content_digest),
            )
        })
        .collect()
}

fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn build_request(
    workspace: &Path,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    inputs: Vec<Input>,
    launch_digest: &str,
    executable_digest: &str,
    operation_id: &str,
) -> Result<Request, String> {
    let workspace = lossy(workspace);
    Request::new(
        argv,
        &workspace,
        &clean_environment(environment),
        Policy::new(&workspace)?,
        inputs,
        launch_digest,
        executable_digest,
        operation_id,
    )
}

fn path_env(environment: &BTreeMap<String, String>) -> &str {
    environment.get("PATH").map_or("", String::as_str)
}

/// One exact local test, lint or diagnostic command.
pub(crate) fn run_node(launch: &Launch, execution: &Value) -> Result<ContainedOutcome, String> {
    let manager = lowered(launch.manager);
    if !matches!(manager.as_str(), "npx" | "bunx") {
        return Err("manager is not a Node runner".to_owned());
    }
    let workspace = workspace_for(launch)?;
    let evidence = build_local_node_runner_evidence(&manager, launch.argv, execution, &workspace)?
        .ok_or_else(|| "runner evidence could not be built".to_owned())?;
    if !evidence.complete {
        return Err("runner evidence was incomplete".to_owned());
    }
    let (Some(executable_path), Some(executable_hash)) = (
        evidence.executable_path.as_deref(),
        evidence.executable_hash.as_deref(),
    ) else {
        return Err("runner identity was incomplete".to_owned());
    };
    let executable = Path::new(executable_path);
    let relative = lossy(
        executable
            .strip_prefix(&workspace)
            .map_err(|_| "runner lies outside the workspace".to_owned())?,
    );
    reject_external_node_modules(&workspace)?;
    let (workspace_digest, inputs) = complete_workspace_snapshot(&workspace, true)?;
    let executable_digest = file_sha256(executable)?;
    let node_path = resolve_tool("node", path_env(launch.environment), launch.shim_directory)?;
    let node_digest = file_sha256(Path::new(&node_path))?;
    if format!("sha256:{executable_digest}") != executable_hash {
        return Err("runner identity changed before execution".to_owned());
    }
    let snapshot = digests_of(&inputs);
    let package_manifest = format!("node_modules/{}/package.json", evidence.runner);
    let expected: [(&str, Option<&str>); 4] = [
        ("package.json", evidence.root_manifest_hash.as_deref()),
        (
            evidence.lockfile_name.as_str(),
            evidence.lockfile_hash.as_deref(),
        ),
        (
            package_manifest.as_str(),
            evidence.package_manifest_hash.as_deref(),
        ),
        (relative.as_str(), Some(executable_hash)),
    ];
    if expected
        .iter()
        .any(|(path, digest)| snapshot.get(path).map(String::as_str) != *digest)
    {
        return Err("workspace identity changed before execution".to_owned());
    }
    if evidence
        .input_files
        .iter()
        .any(|path| !snapshot.contains_key(path.as_str()))
    {
        return Err("requested input was not in the protected snapshot".to_owned());
    }
    let launch_digest = framed_digest(&json!({
        "runner_evidence": evidence.binding_digest,
        "workspace_digest": workspace_digest,
        "executable_digest": executable_digest,
        "node_digest": node_digest,
        "runner_args": evidence.runner_args,
    }))?;
    let mut argv = vec![node_path, relative];
    argv.extend(evidence.runner_args.iter().cloned());
    let request = build_request(
        &workspace,
        &argv,
        launch.environment,
        inputs,
        &launch_digest,
        &node_digest,
        evidence.operation_id,
    )?;
    execute_and_decide(
        &request,
        launch.timeout_seconds,
        ExitPolicy::AnyExit,
        &DecisionLabels {
            operation_id: evidence.operation_id,
            producer_ref: "containment:local-node-v1",
            reason_code: None,
        },
    )
}

fn compiler_args(argv: &[String]) -> Option<&[String]> {
    argv.iter()
        .position(|token| token == "tsc")
        .map(|index| &argv[index + 1..])
}

/// One exact compiler check from the caller's TypeScript launch evidence.
pub(crate) fn run_typescript(
    launch: &Launch,
    execution: &Value,
) -> Result<ContainedOutcome, String> {
    if lowered(launch.manager) != "npx" {
        return Err("manager is not npx".to_owned());
    }
    let workspace = workspace_for(launch)?;
    let evidence = execution
        .get("typescript_launch")
        .filter(|value| value.is_object())
        .ok_or_else(|| "typescript launch evidence missing".to_owned())?;
    let complete = evidence.get("status").and_then(Value::as_str) == Some("complete")
        && evidence.get("direct_silent_verification") != Some(&Value::Bool(true));
    if !complete {
        return Err("typescript launch evidence was incomplete".to_owned());
    }
    let executable = execution
        .get("local_executable")
        .filter(|value| value.is_object());
    let compiler_path = executable
        .and_then(|item| item.get("resolved_path"))
        .and_then(Value::as_str)
        .ok_or_else(|| "compiler identity missing".to_owned())?;
    if executable
        .and_then(|item| item.get("content_hash"))
        .and_then(Value::as_str)
        .is_none()
    {
        return Err("compiler identity missing".to_owned());
    }
    let compiler = Path::new(compiler_path);
    let package_root = compiler
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "compiler is not inside a package".to_owned())?;
    let named = |path: &Path, name: &str| path.file_name().is_some_and(|file| file == name);
    if !named(package_root, "typescript")
        || !package_root
            .parent()
            .is_some_and(|parent| named(parent, "node_modules"))
    {
        return Err("compiler is not the local typescript package".to_owned());
    }
    if package_root != workspace.join("node_modules").join("typescript") {
        return Err("compiler is not the workspace typescript package".to_owned());
    }
    let args = compiler_args(launch.argv).ok_or_else(|| "tsc argument missing".to_owned())?;
    let binding = evidence
        .get("binding_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "typescript evidence digest missing".to_owned())?;
    let sources: Vec<String> = evidence
        .get("source_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let ts = typescript_snapshot_inputs(&workspace, package_root, &sources)?;
    let compiler_digest = file_sha256(compiler)?;
    let node_path = resolve_tool("node", path_env(launch.environment), launch.shim_directory)?;
    let node_digest = file_sha256(Path::new(&node_path))?;
    let launch_digest = framed_digest(&json!({
        "typescript_evidence": binding,
        "tree_digest": ts.tree_digest,
        "closure_digest": ts.closure_digest,
        "compiler_digest": compiler_digest,
        "node_digest": node_digest,
        "compiler_args": args,
    }))?;
    let mut argv = vec![node_path, "node_modules/typescript/bin/tsc".to_owned()];
    argv.extend(args.iter().cloned());
    let mut inputs = ts.package_inputs;
    inputs.extend(ts.closure_inputs);
    let request = build_request(
        &workspace,
        &argv,
        launch.environment,
        inputs,
        &launch_digest,
        &node_digest,
        "typecheck",
    )?;
    execute_and_decide(
        &request,
        launch.timeout_seconds,
        ExitPolicy::ZeroExit,
        &DecisionLabels {
            operation_id: "typecheck",
            producer_ref: "containment:typescript-v1",
            reason_code: Some("routine-typecheck-contained"),
        },
    )
}

/// One exact result-only Bun package script.
pub(crate) fn run_package_script(launch: &Launch) -> Result<ContainedOutcome, String> {
    if lowered(launch.manager) != "bun" {
        return Err("manager is not bun".to_owned());
    }
    let workspace = workspace_for(launch)?;
    let evidence = build_local_package_script_evidence("bun", launch.argv, &workspace)?
        .ok_or_else(|| "script evidence could not be built".to_owned())?;
    if !evidence.complete {
        return Err("script evidence was incomplete".to_owned());
    }
    let (Some(runner_path), Some(runner_hash)) = (
        evidence.executable_path.as_deref(),
        evidence.executable_hash.as_deref(),
    ) else {
        return Err("script runner identity was incomplete".to_owned());
    };
    let runner = Path::new(runner_path);
    let relative = lossy(
        runner
            .strip_prefix(&workspace)
            .map_err(|_| "runner lies outside the workspace".to_owned())?,
    );
    reject_external_node_modules(&workspace)?;
    let (workspace_digest, inputs) = complete_workspace_snapshot(&workspace, false)?;
    let runner_digest = file_sha256(runner)?;
    let bun_path = resolve_tool("bun", path_env(launch.environment), launch.shim_directory)?;
    let bun_digest = file_sha256(Path::new(&bun_path))?;
    if format!("sha256:{runner_digest}") != runner_hash {
        return Err("runner identity changed before execution".to_owned());
    }
    let snapshot = digests_of(&inputs);
    let package = if evidence.runner == "tsc" {
        "typescript"
    } else {
        evidence.runner.as_str()
    };
    let package_manifest = format!("node_modules/{package}/package.json");
    let expected: [(&str, Option<&str>); 4] = [
        ("package.json", evidence.root_manifest_hash.as_deref()),
        ("package-lock.json", evidence.lockfile_hash.as_deref()),
        (
            package_manifest.as_str(),
            evidence.package_manifest_hash.as_deref(),
        ),
        (relative.as_str(), Some(runner_hash)),
    ];
    if expected
        .iter()
        .any(|(path, digest)| snapshot.get(path).map(String::as_str) != *digest)
    {
        return Err("workspace identity changed before execution".to_owned());
    }
    let launch_digest = framed_digest(&json!({
        "script_evidence": evidence.binding_digest,
        "workspace_digest": workspace_digest,
        "runner_digest": runner_digest,
        "bun_digest": bun_digest,
        "runner_args": evidence.runner_args,
    }))?;
    let mut argv = vec![bun_path, relative];
    argv.extend(evidence.runner_args.iter().cloned());
    let request = build_request(
        &workspace,
        &argv,
        launch.environment,
        inputs,
        &launch_digest,
        &bun_digest,
        &evidence.operation_id,
    )?;
    execute_and_decide(
        &request,
        launch.timeout_seconds,
        ExitPolicy::AnyExit,
        &DecisionLabels {
            operation_id: &evidence.operation_id,
            producer_ref: "containment:bun-package-script-v1",
            reason_code: None,
        },
    )
}
