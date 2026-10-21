use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    command: Vec<String>,
    path: PathBuf,
    root: PathBuf,
    roots: Vec<PathBuf>,
    workspace: PathBuf,
    cwd: PathBuf,
    home: Option<PathBuf>,
    executable: PathBuf,
    launch_executable: PathBuf,
    allowed_executables: Vec<PathBuf>,
    private_root: Option<PathBuf>,
    private_home: PathBuf,
    private_tmp: PathBuf,
    platform: String,
    backend_executable: Option<PathBuf>,
    value: String,
    search_path: String,
    read_only_workspace: bool,
    source: BTreeMap<String, String>,
    user_site_root: Option<PathBuf>,
}

pub fn evaluate(operation: &str, input: &Value) -> Value {
    if let Some(result) = crate::contained_argv::evaluate(operation, input)
        .or_else(|| super::contained::evaluate(operation, input))
        .or_else(|| super::profiles::evaluate(operation, input))
        .or_else(|| super::workspace::evaluate(operation, input))
        .or_else(|| super::workspace_linux::evaluate(operation, input))
        .or_else(|| super::workspace_overlay::evaluate(operation, input))
        .or_else(|| super::credentials::evaluate(operation, input))
    {
        return result;
    }
    match serde_json::from_value::<Input>(input.clone()) {
        Ok(input) => match evaluate_inner(operation, &input) {
            Ok(value) => json!({"value": value}),
            Err(error) => crate::restricted_command::error_reply(error),
        },
        Err(_) => json!({"reason_code": PYTEST_INVALID_COMMAND_REASON_CODE,
                        "message": "Invalid restricted execution request."}),
    }
}

fn evaluate_inner(operation: &str, input: &Input) -> Result<Value, RestrictedPytestError> {
    let value = match operation {
        "normalized_command" => json!(normalized_command(&input.command)?),
        "python_args_target_pytest" => json!(python_args_target_pytest(&input.command)),
        "resolve_workspace" => json!(resolve_workspace_with_home(
            &input.path,
            input.home.as_deref()
        )?),
        "resolve_cwd" => json!(resolve_cwd(&input.path, &input.workspace)?),
        "resolve_executable" => json!(resolve_executable(
            &input.value,
            &input.cwd,
            &input.search_path
        )?),
        "locate_executable" => json!(locate_executable(
            &input.value,
            &input.cwd,
            &input.search_path
        )?),
        "select_backend" => json!(select_backend(
            &input.platform,
            input.backend_executable.as_deref(),
            &input.search_path
        )?),
        "resolve_pytest_executable" => json!(resolve_pytest_executable(
            &input.command,
            &input.cwd,
            &input.workspace,
            &input.search_path
        )?),
        "allowed_executables" => json!(allowed_executables(
            &input.executable,
            &input.launch_executable,
            &input.command,
            &input.cwd,
            &input.workspace,
            &input.search_path
        )?),
        "restricted_pythonpath" => json!(restricted_pythonpath(
            &input.value,
            &input.workspace,
            &input.cwd
        )?),
        "path_is_within" => json!(path_is_within(&input.path, &input.root)),
        "path_is_within_any" => json!(path_is_within_any(&input.path, &input.roots)),
        "first_symlink_expansion" => json!(first_symlink_expansion(&input.path)),
        "runtime_distribution_root" => json!(runtime_distribution_root(&input.path)),
        "environment" => json!(super::environment::filter(
            &input.source,
            &input.workspace,
            &input.cwd,
            &input.private_home,
            &input.private_tmp,
            &input.allowed_executables,
            input
                .user_site_root
                .as_deref()
                .is_some_and(super::user_site::grantable)
        )?),
        "user_site_link_target" => json!(super::user_site::link_target(&input.source)),
        "private_links" => json!(super::toolchains::private_links(
            &input.private_tmp,
            &input.roots
        )
        .into_iter()
        .map(|(link, target)| json!({"link": link, "target": target}))
        .collect::<Vec<_>>()),
        "runtime_roots" => json!(runtime_roots(
            &input.allowed_executables,
            &input.workspace,
            input.private_root.as_deref()
        )),
        "symlink_runtime_roots" => json!(symlink_runtime_roots(&input.path)),
        "dedupe_parent_paths" => json!(dedupe_parent_paths(&input.roots)),
        "ancestor_paths" => json!(ancestor_paths(&input.roots)),
        "prepare" => prepare(input)?,
        _ => {
            return Err(RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Unknown restricted execution operation.",
            ))
        }
    };
    Ok(value)
}

fn prepare(input: &Input) -> Result<Value, RestrictedPytestError> {
    let command = normalized_command(&input.command)?;
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    let workspace = resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
    let cwd = resolve_cwd(&input.cwd, &workspace)?;
    let (launch, executable) =
        resolve_pytest_executable(&command, &cwd, &workspace, &input.search_path)?;
    let allowed = allowed_executables(
        &executable,
        &launch,
        &command,
        &cwd,
        &workspace,
        &input.search_path,
    )?;
    let mut command = command;
    command[0] = launched_path(&launch, &executable)
        .to_string_lossy()
        .into_owned();
    let mut denied = vec![
        "host-home-read",
        "host-secret-environment",
        "network",
        "docker-socket",
        "write-outside-workspace-and-private-temp",
        "unapproved-process-exec",
        "privileged-operation",
    ];
    if input.read_only_workspace {
        denied.extend(["workspace-write", "workspace-credential-read"]);
    }
    Ok(
        json!({"profile_version": if input.read_only_workspace {"pytest-readonly-v2"} else {"pytest-restricted-v1"},
        "backend": backend, "backend_executable": backend_executable, "workspace": workspace,
        "cwd": cwd, "command": command, "executable": executable, "allowed_executables": allowed,
        "denied_capabilities": denied}),
    )
}

/// The path the contained run execs.
///
/// The launcher, so a virtual environment keeps the prefix its own
/// `bin/python` names. A `/usr/bin` shim is the exception: running it inside
/// containment would repeat the `xcode-select` lookup the resolution already
/// answered, which is the failure that resolution exists to avoid, so the tool
/// it forwards to takes its place.
pub(super) fn launched_path(launch: &Path, executable: &Path) -> PathBuf {
    launch
        .canonicalize()
        .ok()
        .and_then(|path| super::developer_shim::forwarded_tool(&path))
        .filter(|forwarded| forwarded == executable)
        .unwrap_or_else(|| launch.to_path_buf())
}

const SEALED: &[&str] = &["/bin", "/System", "/usr/bin"];

fn symlink_runtime_roots(executable: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let mut current = path_absolute(executable);
    for _ in 0..16 {
        let Some(expansion) = first_symlink_expansion(&current) else {
            break;
        };
        current = expansion;
        if SEALED
            .iter()
            .any(|root| path_is_within(&current, Path::new(root)))
        {
            continue;
        }
        let root = runtime_distribution_root(&current);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

pub(super) fn runtime_roots(
    executables: &[PathBuf],
    workspace: &Path,
    private: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for executable in executables {
        if private.is_some_and(|root| path_is_within(executable, root)) {
            continue;
        }
        // A venv launcher that links straight to its base interpreter still
        // needs its own `pyvenv.cfg` and site-packages readable.
        if let Some(root) = super::venv::launcher_root(executable)
            .filter(|root| !path_is_within(root, workspace) && !roots.contains(root))
        {
            roots.push(root);
        }
        let aliases = symlink_runtime_roots(executable);
        if !aliases.is_empty() {
            for root in aliases {
                if !roots.contains(&root) {
                    roots.push(root);
                }
            }
            continue;
        }
        if path_is_within(executable, workspace)
            || SEALED
                .iter()
                .any(|root| path_is_within(executable, Path::new(root)))
        {
            continue;
        }
        let parent = executable.parent().unwrap_or(Path::new("/"));
        let root = if parent.file_name() == Some(OsStr::new("bin")) {
            parent.parent().unwrap_or(Path::new("/"))
        } else {
            parent
        }
        .to_path_buf();
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

/// The framework versions a contained run has to execute as a subpath rather
/// than by name.
///
/// A framework interpreter is not one binary. Apple's `python3.9` re-execs
/// `Versions/<x>/Resources/Python.app/Contents/MacOS/Python` to get a GUI
/// session, so a profile that lists only the executables it was given denies
/// the second exec and the run dies with `posix_spawn: ... Undefined error: 0`.
/// Granting the version directory covers the binary and whatever it re-execs
/// inside its own framework, and nothing else: the directory is part of a
/// read-only toolchain the caller already runs outside containment, and the
/// privileged names stay denied alongside it.
pub(super) fn framework_exec_roots(executables: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for executable in executables {
        let Some(root) = framework_version_root(executable) else {
            continue;
        };
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

/// `Versions/<x>` inside the nearest enclosing `*.framework`, when the path
/// sits in one. The version directory rather than the framework, so one
/// version's grant does not reach the others.
fn framework_version_root(executable: &Path) -> Option<PathBuf> {
    let absolute = path_absolute(executable);
    let mut version = None;
    for ancestor in absolute.ancestors() {
        let name = ancestor.file_name()?;
        if ancestor.parent()?.file_name() == Some(OsStr::new("Versions")) {
            version = Some(ancestor.to_path_buf());
        }
        if name.to_string_lossy().ends_with(".framework") {
            return version.filter(|root| root.is_dir());
        }
    }
    None
}

pub(super) fn dedupe_parent_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut sorted: Vec<PathBuf> = paths
        .iter()
        .filter_map(|path| resolve_nonstrict(path).ok())
        .collect();
    sorted.sort_by_key(|path| (path.components().count(), path.clone()));
    sorted.dedup();
    let mut result: Vec<PathBuf> = Vec::new();
    for path in sorted {
        if !result.iter().any(|parent| path_is_within(&path, parent)) {
            result.push(path);
        }
    }
    result
}

pub(super) fn ancestor_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for path in paths {
        for parent in path.ancestors() {
            if parent != Path::new("/") && !result.iter().any(|item| item == parent) {
                result.push(parent.to_path_buf());
            }
        }
    }
    result
}
