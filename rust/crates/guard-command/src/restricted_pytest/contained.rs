//! Native preparation for contained Node/Vitest and direct inline evaluation.
use super::*;
use crate::contained_argv::{
    bun_runner_entry_launch, bun_vitest_invocation, contained_runner_invocation, inline_eval,
    node_runtime_args, node_script_index, python_runtime_args, tsx_runner_test_mode,
    tsx_test_invocation, tsx_test_runner_flags,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

#[path = "contained_bun.rs"]
mod bun;
#[path = "contained_inline.rs"]
mod inline;
#[path = "contained_vitest.rs"]
mod vitest;
pub use bun::planned_route_argv;
use inline::prepare_inline;
use vitest::{prepare_vitest, readonly_config_arguments};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    command: Vec<String>,
    workspace: PathBuf,
    cwd: PathBuf,
    platform: String,
    backend_executable: Option<PathBuf>,
    search_path: String,
    home: Option<PathBuf>,
    path: PathBuf,
    value: String,
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if !matches!(
        operation,
        "prepare_node"
            | "prepare_vitest"
            | "prepare_inline"
            | "approved_node"
            | "nearest_project_root"
            | "readonly_config_arguments"
    ) {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| {
            RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Invalid restricted execution request.",
            )
        })
        .and_then(|input| match operation {
            "prepare_node" => prepare_node(&input),
            "prepare_vitest" => prepare_vitest(&input),
            "prepare_inline" => prepare_inline(&input),
            "approved_node" => Ok(json!(approved_node(
                &input.path,
                &input.workspace,
                input.home.as_deref()
            ))),
            "nearest_project_root" => Ok(json!(nearest_project_root(
                &input.cwd,
                &input.workspace,
                &input.value
            )?)),
            "readonly_config_arguments" => Ok(json!(readonly_config_arguments(
                &input.command,
                &input.path
            ))),
            _ => unreachable!(),
        });
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

fn invalid_node(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new("node_test_restricted_invalid_command", message)
}

/// The request HOME, else the process HOME, else the account home; canonical.
fn request_home(home: Option<&Path>) -> Option<PathBuf> {
    if let Some(home) = home {
        return home.canonicalize().ok();
    }
    std::env::var_os("HOME")
        .and_then(|raw| {
            let path = PathBuf::from(&raw);
            if raw.is_empty() || !path.is_absolute() {
                None
            } else {
                path.canonicalize().ok()
            }
        })
        .or_else(host_home_directory)
}

/// Where a version manager keeps the Node releases it installed, relative to
/// a home. Each entry is one manager's own tree and nothing else: nvm, fnm,
/// Volta, asdf and mise. They are named one by one, rather than hidden
/// directories below a home being admitted as a class, because that class
/// holds the directories a contained run must never execute from.
/// `~/.hol-guard/package-shims/bin` holds shims that hand a launch back to
/// Guard instead of running the runtime, and `~/.claude`, `~/.codex` and
/// `~/.omp` hold agent state; no entry here can spell any of them.
pub(super) const NODE_MANAGER_ROOTS: &[&str] = &[
    ".nvm/versions/node",
    ".fnm/node-versions",
    ".local/share/fnm/node-versions",
    ".volta/tools/image/node",
    ".asdf/installs/nodejs",
    ".local/share/mise/installs/node",
];
/// Where Bun's own installer puts the runtime, relative to a home, and the
/// version-manager trees that install Bun instead. The installer directory
/// holds the binary itself; the others hold a release per version, like
/// [`NODE_MANAGER_ROOTS`].
const BUN_INSTALL_ROOT: &str = ".bun/bin";
const BUN_MANAGER_ROOTS: &[&str] = &[".asdf/installs/bun", ".local/share/mise/installs/bun"];

/// Every home a runtime may be installed under: the one the request names and
/// this account's own, canonical and without repeats.
///
/// The request HOME is not always the account's. A session Guard supervises
/// is started with the HOME its harness chose, while the runtime the caller
/// actually runs was installed by nvm or Bun's installer under the account's
/// home. Reading only the request's home refused that runtime and the
/// contained run died with exit 126 before it executed anything, which is why
/// both are read here, as `toolchains::homes` already does for every other
/// root a contained run is granted.
fn runtime_homes(home: Option<&Path>) -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    for candidate in request_home(home).into_iter().chain(host_home_directory()) {
        let canonical = candidate.canonicalize().unwrap_or(candidate);
        if !homes.contains(&canonical) {
            homes.push(canonical);
        }
    }
    homes
}

/// `relatives` below each home, canonical where the directory resolves.
///
/// The executable a plan judges is canonical, so the roots it is compared
/// against are canonical too: a home whose `.nvm` is a link, which is how
/// several dotfile managers lay a profile out, otherwise never matched the
/// path the runtime actually resolved to.
pub(super) fn manager_roots(homes: &[PathBuf], relatives: &[&str]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for home in homes {
        for relative in relatives {
            let joined = home.join(relative);
            let root = joined.canonicalize().unwrap_or(joined);
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    roots
}

/// Whether `executable` is the runtime a version manager installed below one
/// of `roots`: `<root>/<version>/bin/<name>`, or the extra `installation`
/// level fnm writes. Only those two shapes, so a program that merely happens
/// to sit somewhere inside a manager's tree is not reached through this rule.
pub(super) fn managed_runtime(executable: &Path, roots: &[PathBuf]) -> bool {
    static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^v?\d+(\.\d+){0,2}$").unwrap());
    let Some(parent) = executable.parent() else {
        return false;
    };
    if parent.file_name() != Some(OsStr::new("bin")) {
        return false;
    }
    let Some(mut version) = parent.parent() else {
        return false;
    };
    if version.file_name() == Some(OsStr::new("installation")) {
        let Some(outer) = version.parent() else {
            return false;
        };
        version = outer;
    }
    version
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| VERSION.is_match(name))
        && version
            .parent()
            .is_some_and(|root| roots.iter().any(|candidate| candidate == root))
}

/// Whether `executable` is a Node a version manager installed under one of
/// the caller's homes.
pub(super) fn managed_node(executable: &Path, home: Option<&Path>) -> bool {
    let homes = runtime_homes(home);
    managed_runtime(executable, &manager_roots(&homes, NODE_MANAGER_ROOTS))
}

/// Whether `executable` is a Bun that Bun's own installer, or a version
/// manager, put under one of the caller's homes.
pub(super) fn managed_bun(executable: &Path, home: Option<&Path>) -> bool {
    let homes = runtime_homes(home);
    let installed = executable.file_name() == Some(OsStr::new("bun"))
        && manager_roots(&homes, &[BUN_INSTALL_ROOT])
            .iter()
            .any(|root| executable.parent() == Some(root.as_path()));
    installed || managed_runtime(executable, &manager_roots(&homes, BUN_MANAGER_ROOTS))
}

fn approved_node(executable: &Path, workspace: &Path, home: Option<&Path>) -> bool {
    let Ok(metadata) = executable.metadata() else {
        return false;
    };
    if ![0, nix::unistd::getuid().as_raw()].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || !matches!(
            executable.file_name().and_then(OsStr::to_str),
            Some("node" | "nodejs")
        )
    {
        return false;
    }
    let trusted = [
        workspace,
        Path::new("/usr/bin"),
        Path::new("/usr/local"),
        Path::new("/opt/homebrew"),
    ]
    .iter()
    .any(|root| path_is_within(executable, root))
        || managed_node(executable, home);
    trusted && native_image(executable)
}

/// ELF or Mach-O, not a script that would choose its own interpreter.
fn native_image(executable: &Path) -> bool {
    let mut magic = [0u8; 4];
    let Ok(mut file) = fs::File::open(executable) else {
        return false;
    };
    file.read_exact(&mut magic).is_ok()
        && matches!(
            &magic,
            b"\x7fELF"
                | b"\xcf\xfa\xed\xfe"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xca\xfe\xba\xbe"
        )
}

fn nearest_project_root(
    cwd: &Path,
    workspace: &Path,
    relative: &str,
) -> Result<PathBuf, RestrictedPytestError> {
    let root = workspace
        .canonicalize()
        .map_err(|_| invalid_node("Project root is unavailable."))?;
    let mut directory = cwd
        .canonicalize()
        .map_err(|_| invalid_node("Working directory is unavailable."))?;
    if !path_is_within(&directory, &root) {
        return Ok(root);
    }
    while directory != root && fs::symlink_metadata(directory.join(relative)).is_err() {
        directory.pop();
    }
    Ok(directory)
}

fn prepare_node(input: &Input) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    // `bun test` shares this profile: the same read-only boundary, a
    // different image approval.
    if Path::new(&argv[0]).file_name().and_then(OsStr::to_str) == Some("bun") {
        return bun::prepare_test(input, &argv);
    }
    let runtime = node_runtime_args(&argv)?;
    let index = 1 + runtime.len();
    if argv.len() <= index
        || !matches!(
            Path::new(&argv[0]).file_name().and_then(OsStr::to_str),
            Some("node" | "nodejs")
        )
        || argv[index] != "--test"
        || argv
            .iter()
            .any(|v| matches!(v.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(invalid_node(
            "Protected Node execution requires direct node --test argv.",
        ));
    }
    let (backend, backend_executable) = select_backend(
        &input.platform,
        input.backend_executable.as_deref(),
        &input.search_path,
    )?;
    let workspace =
        validation::resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
    let cwd = resolve_cwd(&input.cwd, &workspace)?;
    let executable = resolve_executable(&argv[0], &cwd, &input.search_path)?;
    if !approved_node(&executable, &workspace, input.home.as_deref()) {
        return Err(invalid_node(
            "The Node runtime does not resolve to an approved native executable.",
        ));
    }
    let launcher = locate_executable(&argv[0], &cwd, &input.search_path)?;
    let mut allowed = vec![launcher];
    if !allowed.contains(&executable) {
        allowed.push(executable.clone());
    }
    let mut command = vec![executable.to_string_lossy().into_owned()];
    command.extend(runtime);
    command.extend_from_slice(&argv[index..]);
    Ok(
        json!({"profile_version":"node-test-readonly-v1","backend":backend,"backend_executable":backend_executable,
        "workspace":workspace,"cwd":cwd,"executable":executable,"command":command,"allowed_executables":allowed,
        "denied_capabilities":["host-home-read","host-secret-environment","network","docker-socket","workspace-write","workspace-credential-read","unapproved-process-exec","privileged-operation"]}),
    )
}
