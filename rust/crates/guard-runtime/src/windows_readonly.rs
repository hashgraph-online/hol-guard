//! Windows backend for the read-only Python and Node evaluation profiles, and
//! the `contained-readonly-windows` entry the Vite build profile shares
//! (`windows_node_build`).
//!
//! The resident plans `python <script>` / `python -c` launches for an
//! interpreter installed under a trusted install root, `node <script>` /
//! `node -e` launches for an installed Node.js runtime, and the
//! `contained-readonly-windows` entry runs the plan inside the LPAC snapshot
//! runner: a credential-filtered copy of the workspace, private HOME/TEMP, no
//! network capability and a kill-on-close job. The live workspace and the
//! user profile are never granted to the container.
use guard_command::contained_argv::{
    inline_eval, node_runtime_args, node_script_index, python_runtime_args,
};
use guard_command::restricted_command::{normalized_command, RestrictedPytestError};
use regex::Regex;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub(crate) const PROFILE: &str = "python-eval-readonly-v1";
pub(crate) const NODE_PROFILE: &str = "node-eval-readonly-v1";
pub(crate) const BACKEND: &str = "windows-appcontainer";
pub(crate) const COMMAND: &str = "contained-readonly-windows";
const INVALID: &str = "inline_eval_invalid_command";
const UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";
const MAX_TIMEOUT_SECONDS: u64 = 86_400;
const MAX_ENTRIES: usize = 20_000;
const MAX_BYTES: usize = 256 * 1024 * 1024;
const OUTPUT_CAP: usize = 1024 * 1024;
/// A build's installed dependencies; a mid-sized Vite app is well below.
const MAX_DEPENDENCY_ENTRIES: usize = 200_000;
const MAX_DEPENDENCY_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Never needed by an installed interpreter and often large; `.git` may also
/// hold remote credentials in its config.
const WITHHELD_DIRECTORIES: [&str; 4] = [".git", ".venv", "node_modules", "__pycache__"];
/// Presentation and locale only; nothing here selects code to load.
const INHERITED_ENVIRONMENT: [&str; 22] = [
    "SystemRoot",
    "SystemDrive",
    "windir",
    "PATHEXT",
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "OS",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "TZ",
    "CI",
    "NO_COLOR",
    "FORCE_COLOR",
    "TERM",
    "COLUMNS",
    "LINES",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
];

fn error(reason_code: &str, message: &str) -> RestrictedPytestError {
    RestrictedPytestError {
        reason_code: reason_code.to_owned(),
        message: message.to_owned(),
    }
}

/// `canonicalize` returns verbatim paths; callers and Python use drive paths.
pub(crate) fn canonical(path: &Path) -> Option<PathBuf> {
    let resolved = path.canonicalize().ok()?;
    let text = resolved.to_str()?;
    Some(match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => resolved,
    })
}

fn trusted_executable(path: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let executable = canonical(path)
        .filter(|path| path.is_file())
        .ok_or_else(|| error(UNAVAILABLE, "The Python interpreter could not be resolved."))?;
    let trusted = guard_runtime_windows_process::trusted_install_roots()
        .iter()
        .filter_map(|root| canonical(root))
        .any(|root| executable.starts_with(root));
    if !trusted {
        return Err(error(
            UNAVAILABLE,
            "Protected evaluation on Windows requires a Python installed for all users.",
        ));
    }
    Ok(executable)
}

/// The first `PATH` match, as the shell would run it; a later trusted match
/// is never substituted for an untrusted first one.
fn resolve_executable(name: &str, search_path: &str) -> Result<PathBuf, RestrictedPytestError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return trusted_executable(candidate);
    }
    if candidate.components().count() != 1 {
        return Err(error(
            INVALID,
            "Relative interpreter paths are not supported.",
        ));
    }
    match locate(name, search_path) {
        Some(path) => trusted_executable(&path),
        None => Err(error(
            UNAVAILABLE,
            "The Python interpreter could not be resolved.",
        )),
    }
}

fn locate(name: &str, search_path: &str) -> Option<PathBuf> {
    let names: Vec<String> = if Path::new(name).extension().is_some() {
        vec![name.to_owned()]
    } else {
        vec![name.to_owned(), format!("{name}.exe")]
    };
    // The shell skips a directory without `python3`, such as a virtualenv's
    // Scripts, so the whole PATH is searched for the exact name first.
    first_on_path(&names, search_path).or_else(|| {
        // All-users installs ship only `python.exe`; it stands in for a
        // missing `python3`, and PATH order still decides which one.
        name.eq_ignore_ascii_case("python3")
            .then(|| first_on_path(&["python.exe".to_owned()], search_path))
            .flatten()
    })
}

pub(crate) fn first_on_path(names: &[String], search_path: &str) -> Option<PathBuf> {
    std::env::split_paths(search_path)
        .filter(|directory| directory.is_absolute())
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|path| path.is_file())
}

pub(crate) fn workspace_and_cwd(
    workspace: &Path,
    cwd: &Path,
) -> Result<(PathBuf, PathBuf), RestrictedPytestError> {
    let invalid = || {
        error(
            "pytest_restricted_invalid_workspace",
            "The workspace is not a directory.",
        )
    };
    let workspace = canonical(workspace)
        .filter(|path| path.is_dir())
        .ok_or_else(invalid)?;
    let cwd = canonical(cwd)
        .filter(|path| path.is_dir() && path.starts_with(&workspace))
        .ok_or_else(invalid)?;
    Ok((workspace, cwd))
}

fn python_name(executable: &str) -> bool {
    let name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    stem == "python"
        || stem == "python3"
        || stem.strip_prefix("python3.").is_some_and(|minor| {
            !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn node_name(executable: &str) -> bool {
    let name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        name.strip_suffix(".exe").unwrap_or(&name),
        "node" | "nodejs"
    )
}

/// The `node` the shell would run: the first `PATH` match, which must be a
/// full Node.js image (`windows_node_build::node_executable`).
fn resolve_node(name: &str, search_path: &str) -> Result<PathBuf, RestrictedPytestError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return crate::windows_node_build::node_executable(candidate);
    }
    if candidate.components().count() != 1 {
        return Err(error(
            INVALID,
            "Relative interpreter paths are not supported.",
        ));
    }
    let names = if candidate.extension().is_some() {
        vec![name.to_owned()]
    } else {
        vec![name.to_owned(), format!("{name}.exe")]
    };
    let path = first_on_path(&names, search_path)
        .ok_or_else(|| error(UNAVAILABLE, "The Node.js runtime could not be resolved."))?;
    crate::windows_node_build::node_executable(&path)
}

fn plan_inline(input: &Value) -> Result<Value, RestrictedPytestError> {
    let invalid = || error(INVALID, "Protected evaluation requires direct inline argv.");
    let command: Vec<String> = input
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(invalid)?;
    let path = |key: &str| input.get(key).and_then(Value::as_str).map(PathBuf::from);
    let (workspace, cwd) = workspace_and_cwd(
        &path("workspace").ok_or_else(invalid)?,
        &path("cwd").ok_or_else(invalid)?,
    )?;
    let argv = normalized_command(&command)?;
    let node = node_name(&argv[0]);
    if !inline_eval(&argv)? || !(node || python_name(&argv[0])) {
        return Err(invalid());
    }
    let (index, inline) = if node {
        (1 + node_runtime_args(&argv)?.len(), &["-e", "--eval"][..])
    } else {
        (
            1 + python_runtime_args(&argv).unwrap_or_default().len(),
            &["-c", "-m"][..],
        )
    };
    if !argv
        .get(index)
        .is_some_and(|flag| inline.contains(&flag.as_str()))
    {
        // Node skips the same neutral flags `inline_eval` admitted.
        let index = if node {
            node_script_index(&argv, index).ok_or_else(invalid)?
        } else {
            index
        };
        let script = argv
            .get(index)
            .and_then(|script| canonical(&cwd.join(script)));
        if !script.is_some_and(|script| script.is_file() && script.starts_with(&workspace)) {
            return Err(error(INVALID, "Test script is not in the workspace."));
        }
    }
    let search_path = input
        .get("search_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let executable = if node {
        resolve_node(&argv[0], search_path)?
    } else {
        resolve_executable(&argv[0], search_path)?
    };
    let runtime = std::env::current_exe()
        .ok()
        .and_then(|path| canonical(&path))
        .ok_or_else(|| error(UNAVAILABLE, "The Guard runtime path is unavailable."))?;
    let mut launch = vec![executable.to_string_lossy().into_owned()];
    launch.extend(argv[1..].iter().cloned());
    Ok(json!({
        "profile_version": if node { NODE_PROFILE } else { PROFILE },
        "backend": BACKEND,
        "backend_executable": runtime,
        "workspace": workspace,
        "cwd": cwd,
        "executable": executable,
        "command": launch,
        "allowed_executables": [executable],
        "denied_capabilities": ["host-home-read","host-secret-environment","network","workspace-write","workspace-credential-read","privileged-operation"],
    }))
}

/// Resident `prepare_inline` on Windows.
pub(crate) fn prepare_inline(input: &Value) -> Value {
    match plan_inline(input) {
        Ok(plan) => json!({ "value": plan }),
        Err(error) => json!({ "reason_code": error.reason_code, "message": error.message }),
    }
}

pub(crate) fn is_command(arguments: &[String]) -> bool {
    arguments.first().map(String::as_str) == Some(COMMAND)
}

struct Launch {
    workspace: PathBuf,
    cwd: PathBuf,
    timeout: Duration,
    executable: PathBuf,
    arguments: Vec<OsString>,
    /// A Node.js launch, which takes no Python settings.
    node: bool,
    build: Option<NodeBuild>,
}

/// The staged dependencies and published outputs of a node build launch.
struct NodeBuild {
    dependencies: Vec<(PathBuf, PathBuf)>,
    outputs: Vec<PathBuf>,
}

fn parse(arguments: &[String]) -> Result<Launch, RestrictedPytestError> {
    let invalid = || error(INVALID, "Invalid protected evaluation launch.");
    let (options, command) = arguments
        .iter()
        .position(|argument| argument == "--")
        .map(|index| (&arguments[1..index], &arguments[index + 1..]))
        .ok_or_else(invalid)?;
    let (mut profile, mut workspace, mut cwd, mut timeout) = (None, None, None, None);
    let mut outputs = Vec::new();
    for pair in options.chunks(2) {
        let [name, value] = pair else {
            return Err(invalid());
        };
        let slot = match name.as_str() {
            "--profile" => &mut profile,
            "--workspace" => &mut workspace,
            "--cwd" => &mut cwd,
            "--timeout-seconds" => &mut timeout,
            "--output" => {
                outputs.push(PathBuf::from(value));
                continue;
            }
            _ => return Err(invalid()),
        };
        if slot.replace(value.as_str()).is_some() {
            return Err(invalid());
        }
    }
    let (build, node) = match profile {
        None => (false, false),
        Some(NODE_PROFILE) => (false, true),
        Some(profile) if profile == crate::windows_node_build::PROFILE => (true, true),
        Some(_) => return Err(invalid()),
    };
    if build == outputs.is_empty() {
        return Err(invalid());
    }
    let timeout = timeout
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| (1..=MAX_TIMEOUT_SECONDS).contains(seconds))
        .ok_or_else(invalid)?;
    let (workspace, cwd) = workspace_and_cwd(
        Path::new(workspace.ok_or_else(invalid)?),
        Path::new(cwd.ok_or_else(invalid)?),
    )?;
    let (executable, rest) = command.split_first().ok_or_else(invalid)?;
    if node && !build {
        // Node's JavaScript realpath lstats the drive root, which an LPAC
        // token cannot do; the snapshot holds no links to resolve.
        let arguments = ["--preserve-symlinks", "--preserve-symlinks-main"]
            .into_iter()
            .map(OsString::from)
            .chain(rest.iter().map(OsString::from))
            .collect();
        return Ok(Launch {
            workspace,
            cwd,
            timeout: Duration::from_secs(timeout),
            executable: crate::windows_node_build::node_executable(Path::new(executable))?,
            arguments,
            node: true,
            build: None,
        });
    }
    if !build {
        if !python_name(executable) {
            return Err(invalid());
        }
        return Ok(Launch {
            workspace,
            cwd,
            timeout: Duration::from_secs(timeout),
            executable: trusted_executable(Path::new(executable))?,
            arguments: rest.iter().map(OsString::from).collect(),
            node: false,
            build: None,
        });
    }
    let executable = crate::windows_node_build::node_executable(Path::new(executable))?;
    let runtime = rest
        .iter()
        .take_while(|argument| crate::windows_node_build::runtime_option(argument))
        .count();
    if runtime > 1 {
        return Err(invalid());
    }
    let (entry, tail) = rest[runtime..].split_first().ok_or_else(invalid)?;
    let dependencies = crate::windows_node_build::dependencies(&workspace, &cwd)?;
    let relative_cwd = cwd.strip_prefix(&workspace).map_err(|_| invalid())?;
    let entry =
        crate::windows_node_build::staged_entry(Path::new(entry), &dependencies, relative_cwd)
            .ok_or_else(invalid)?;
    let outputs = outputs
        .iter()
        .map(|output| crate::windows_node_build::output_location(output, &workspace))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid)?;
    // Node's JavaScript realpath lstats the drive root before walking a path,
    // which an LPAC token cannot do. The staged copy holds no links, so its
    // module loaders resolve the same files without that realpath.
    let mut arguments: Vec<OsString> = ["--preserve-symlinks", "--preserve-symlinks-main"]
        .into_iter()
        .chain(rest[..runtime].iter().map(String::as_str))
        .map(OsString::from)
        .collect();
    arguments.push(entry.into_os_string());
    arguments.extend(tail.iter().map(OsString::from));
    Ok(Launch {
        workspace,
        cwd,
        timeout: Duration::from_secs(timeout),
        executable,
        arguments,
        node: true,
        build: Some(NodeBuild {
            dependencies,
            outputs,
        }),
    })
}

fn environment(executable: &Path, node: bool) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<(OsString, OsString)> = INHERITED_ENVIRONMENT
        .iter()
        .filter(|name| !node || !name.starts_with("PYTHON"))
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect();
    let mut path = vec![executable.parent().unwrap_or(executable).to_path_buf()];
    if let Some(root) = std::env::var_os("SystemRoot") {
        let root = PathBuf::from(root);
        path.push(root.join("System32"));
        path.push(root);
    }
    if let Ok(path) = std::env::join_paths(path) {
        environment.push(("PATH".into(), path));
    }
    if !node {
        environment.push(("PYTHONNOUSERSITE".into(), "1".into()));
        environment.push(("PYTHONDONTWRITEBYTECODE".into(), "1".into()));
    }
    environment
}

fn withheld(patterns: &[Regex]) -> impl Fn(&Path) -> bool + '_ {
    move |relative: &Path| {
        let text = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        relative.components().any(|component| {
            WITHHELD_DIRECTORIES
                .iter()
                .any(|name| component.as_os_str().eq_ignore_ascii_case(name))
        }) || patterns.iter().any(|pattern| pattern.is_match(&text))
    }
}

/// Dependencies keep their own bulky directories; only credential material
/// and Git metadata stay out.
fn dependency_withheld(patterns: &[Regex]) -> impl Fn(&Path) -> bool + '_ {
    move |relative: &Path| {
        let text = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        relative
            .components()
            .any(|component| component.as_os_str().eq_ignore_ascii_case(".git"))
            || patterns.iter().any(|pattern| pattern.is_match(&text))
    }
}

fn launch(arguments: &[String]) -> Result<i32, RestrictedPytestError> {
    let launch = parse(arguments)?;
    let patterns: Vec<Regex> = guard_command::credential_patterns::patterns()
        .iter()
        .map(|pattern| Regex::new(pattern))
        .collect::<Result<_, _>>()
        .map_err(|_| error(UNAVAILABLE, "Credential patterns are unavailable."))?;
    let withhold = withheld(&patterns);
    let withhold_dependency = dependency_withheld(&patterns);
    let environment = environment(&launch.executable, launch.node);
    let cancel = AtomicBool::new(false);
    if let Some(build) = &launch.build {
        if build.outputs.iter().any(|output| withhold(output)) {
            return Err(error(
                INVALID,
                "Build output must not be a withheld directory.",
            ));
        }
    }
    let build = launch
        .build
        .as_ref()
        .map(|build| guard_contained_process::BuildRun {
            dependencies: &build.dependencies,
            withhold_dependency: &withhold_dependency,
            max_dependency_entries: MAX_DEPENDENCY_ENTRIES,
            max_dependency_bytes: MAX_DEPENDENCY_BYTES,
            outputs: &build.outputs,
            max_output_entries: MAX_ENTRIES,
            max_output_bytes: MAX_BYTES,
        });
    let output = guard_contained_process::run_readonly_snapshot(
        guard_contained_process::ReadonlySnapshotRun {
            workspace: &launch.workspace,
            cwd: &launch.cwd,
            executable: &launch.executable,
            arguments: &launch.arguments,
            environment: &environment,
            withhold: &withhold,
            max_entries: MAX_ENTRIES,
            max_bytes: MAX_BYTES,
            output_cap: OUTPUT_CAP,
            deadline: Instant::now() + launch.timeout,
            cancel: &cancel,
            job_limits: guard_runtime_windows_process::ResourceLimits {
                cpu_user_seconds: Some(launch.timeout.as_secs()),
                committed_memory_bytes: Some(4 * 1024 * 1024 * 1024),
                active_processes: Some(32),
            },
            build,
            stage_executable: launch.node,
        },
    )
    .map_err(|failure| {
        error(
            UNAVAILABLE,
            &format!("Protected evaluation could not run; execution was not completed: {failure}"),
        )
    })?;
    let _ = std::io::stdout().write_all(&output.stdout);
    let _ = std::io::stderr().write_all(&output.stderr);
    if output.output_limited {
        eprintln!("\n[HOL Guard truncated protected evaluation output]");
    }
    if output.timed_out {
        eprintln!(
            "HOL Guard stopped protected evaluation after its {}-second deadline.",
            launch.timeout.as_secs()
        );
        return Ok(124);
    }
    Ok(output.exit_code.unwrap_or(1))
}

/// Entry point for `hol-guard-runtime contained-readonly-windows`.
pub(crate) fn main(arguments: &[String]) -> i32 {
    match launch(arguments) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}: {}", error.reason_code, error.message);
            2
        }
    }
}

#[cfg(test)]
#[path = "windows_readonly_tests.rs"]
mod tests;
