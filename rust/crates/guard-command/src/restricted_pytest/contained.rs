//! Native preparation for contained Node/Vitest and direct inline evaluation.
use super::*;
use crate::contained_argv::{
    bun_vitest_invocation, inline_eval, node_runtime_args, node_script_index, python_runtime_args,
    tsx_test_invocation, vitest_arguments,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

#[path = "contained_bun.rs"]
mod bun;

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

fn nvm_versions_root(home: Option<&Path>) -> Option<PathBuf> {
    request_home(home).map(|home| home.join(".nvm/versions/node"))
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
    let parent = executable.parent().unwrap_or(Path::new("/"));
    let version = parent.parent().unwrap_or(Path::new("/"));
    let nvm = nvm_versions_root(home);
    static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^v\d+\.\d+\.\d+$").unwrap());
    let trusted = [
        workspace,
        Path::new("/usr/bin"),
        Path::new("/usr/local"),
        Path::new("/opt/homebrew"),
    ]
    .iter()
    .any(|root| path_is_within(executable, root))
        || (parent.file_name() == Some(OsStr::new("bin"))
            && version.parent() == nvm.as_deref()
            && version
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|v| VERSION.is_match(v)));
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

fn readonly_config_arguments(args: &[String], manifest: &Path) -> Vec<String> {
    let mut result = args.to_vec();
    if args
        .iter()
        .any(|v| v == "--configLoader" || v.starts_with("--configLoader="))
    {
        return result;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(manifest)
    else {
        return result;
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return result;
    }
    let mut bytes = Vec::new();
    if file.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
        return result;
    }
    let Ok(package) = serde_json::from_slice::<Value>(&bytes) else {
        return result;
    };
    let major = package
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    // Only the comparison is needed; Python's unbounded int may be much larger.
    let digits = major.trim_start_matches('0');
    if package.get("name").and_then(Value::as_str) == Some("vitest")
        && !major.is_empty()
        && major.bytes().all(|v| v.is_ascii_digit())
        && (digits.len() > 1 || digits.parse::<u8>().is_ok_and(|v| v >= 4))
    {
        result.extend(["--configLoader".to_owned(), "runner".to_owned()]);
    }
    result
}

fn prepare_vitest(input: &Input) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    if let Some((script, arguments)) = tsx_test_invocation(&argv)? {
        return prepare_tsx(input, &argv, &script, &arguments);
    }
    let args = vitest_arguments(&input.command)?;
    let runtime = node_runtime_args(&input.command)?;
    let mut workspace = input.workspace.clone();
    let mut cwd = input.cwd.clone();
    if let Some((Some(directory), _)) = bun_vitest_invocation(&input.command) {
        let target = expand_user(Path::new(&directory));
        let target = if target.is_absolute() {
            target
        } else {
            cwd.join(target)
        };
        let original = workspace.canonicalize().ok();
        let resolved = target.canonicalize().ok().filter(|p| p.is_dir());
        let valid = original
            .as_ref()
            .zip(resolved.as_ref())
            .is_some_and(|(root, path)| {
                Path::new(&input.command[0]).file_name() != Some(OsStr::new("bunx"))
                    || path_is_within(path, root)
            });
        if !valid {
            return Err(RestrictedPytestError::new(
                "vitest_restricted_invalid_command",
                "Vitest working directory is unavailable.",
            ));
        }
        cwd = resolved.unwrap();
        if !path_is_within(&cwd, original.as_ref().unwrap()) {
            workspace = cwd.clone();
        }
    }
    let base = Input {
        command: vec!["node".to_owned(), "--test".to_owned()],
        workspace,
        cwd,
        platform: input.platform.clone(),
        backend_executable: input.backend_executable.clone(),
        search_path: input.search_path.clone(),
        home: input.home.clone(),
        ..Input::default()
    };
    let mut plan = prepare_node(&base)?;
    let workspace = Path::new(plan["workspace"].as_str().unwrap());
    let cwd = Path::new(plan["cwd"].as_str().unwrap());
    let modules = nearest_project_root(cwd, workspace, "node_modules/vitest/vitest.mjs")?
        .join("node_modules");
    let entry = modules
        .join("vitest/vitest.mjs")
        .canonicalize()
        .ok()
        .filter(|p| p.is_file() && path_is_within(p, &modules));
    let node = matches!(
        Path::new(&input.command[0])
            .file_name()
            .and_then(OsStr::to_str),
        Some("node" | "nodejs")
    );
    let matching = !node
        || input
            .command
            .get(1 + runtime.len())
            .and_then(|p| cwd.join(p).canonicalize().ok())
            == entry;
    if entry.is_none() || !matching {
        return Err(RestrictedPytestError::new("vitest_restricted_dependency_unavailable",
        "Vitest is not installed inside this workspace. Guard did not download or execute a replacement."));
    }
    let entry = entry.unwrap();
    let args = readonly_config_arguments(&args, &entry.parent().unwrap().join("package.json"));
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.push(entry.to_string_lossy().into_owned());
    command.extend(args);
    plan["profile_version"] = json!("vitest-readonly-v1");
    plan["command"] = json!(command);
    Ok(plan)
}

fn prepare_tsx(
    input: &Input,
    argv: &[String],
    script: &str,
    arguments: &[String],
) -> Result<Value, RestrictedPytestError> {
    let mut plan = prepare_node(&Input {
        command: vec!["node".to_owned(), "--test".to_owned()],
        workspace: input.workspace.clone(),
        cwd: input.cwd.clone(),
        platform: input.platform.clone(),
        backend_executable: input.backend_executable.clone(),
        search_path: input.search_path.clone(),
        home: input.home.clone(),
        ..Input::default()
    })?;
    let workspace = Path::new(plan["workspace"].as_str().unwrap());
    let cwd = Path::new(plan["cwd"].as_str().unwrap());
    let modules = nearest_project_root(cwd, workspace, "node_modules/tsx/dist/loader.mjs")?
        .join("node_modules");
    let loader = modules
        .join("tsx/dist/loader.mjs")
        .canonicalize()
        .ok()
        .filter(|path| path.is_file() && path_is_within(path, &modules));
    let name = Path::new(&argv[0]).file_name().and_then(OsStr::to_str);
    if name == Some("bun") {
        return bun::prepare_eval(input, argv);
    }
    let node = matches!(name, Some("node" | "nodejs"));
    let runtime = if node {
        node_runtime_args(argv)?
    } else {
        vec![]
    };
    let matching = !node
        || argv
            .get(1 + runtime.len())
            .and_then(|value| cwd.join(value).canonicalize().ok())
            == loader
                .as_ref()
                .map(|path| path.parent().unwrap().join("cli.mjs"));
    let Some(loader) = loader.filter(|_| matching) else {
        return Err(RestrictedPytestError::new("vitest_restricted_dependency_unavailable", "tsx is not installed inside this workspace. Guard did not download or execute a replacement."));
    };
    if !cwd
        .join(script)
        .canonicalize()
        .is_ok_and(|path| path.is_file() && path_is_within(&path, workspace))
    {
        return Err(RestrictedPytestError::new(
            "vitest_restricted_invalid_command",
            "Test script is not in the workspace.",
        ));
    }
    let uri = url::Url::from_file_path(loader)
        .map_err(|_| invalid_node("Test loader is unavailable."))?;
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.extend(["--import".to_owned(), uri.into(), script.to_owned()]);
    command.extend_from_slice(arguments);
    plan["profile_version"] = json!("vitest-readonly-v1");
    plan["command"] = json!(command);
    Ok(plan)
}

fn prepare_inline(input: &Input) -> Result<Value, RestrictedPytestError> {
    let argv = normalized_command(&input.command)?;
    if !inline_eval(&argv)? {
        return Err(RestrictedPytestError::new(
            "inline_eval_invalid_command",
            "Protected evaluation requires direct inline argv.",
        ));
    }
    let name = Path::new(&argv[0]).file_name().and_then(OsStr::to_str);
    if name == Some("bun") {
        return bun::prepare_eval(input, &argv);
    }
    let node = matches!(name, Some("node" | "nodejs"));
    let runtime = if node {
        node_runtime_args(&argv)?
    } else {
        python_runtime_args(&argv).unwrap_or_default()
    };
    let index = 1 + runtime.len();
    let script_index = if node {
        node_script_index(&argv, index)
    } else if !matches!(argv[index].as_str(), "-c" | "-m") {
        Some(index)
    } else {
        None
    };
    if let Some(script_index) = script_index {
        let script = input.cwd.join(&argv[script_index]).canonicalize().ok();
        let root = input.workspace.canonicalize().ok();
        if !script
            .as_ref()
            .zip(root.as_ref())
            .is_some_and(|(script, root)| script.is_file() && path_is_within(script, root))
        {
            return Err(RestrictedPytestError::new(
                "inline_eval_invalid_command",
                "Test script is not in the workspace.",
            ));
        }
    }
    let mut plan = if node {
        prepare_node(&Input {
            command: vec![argv[0].clone(), "--test".to_owned()],
            workspace: input.workspace.clone(),
            cwd: input.cwd.clone(),
            platform: input.platform.clone(),
            backend_executable: input.backend_executable.clone(),
            search_path: input.search_path.clone(),
            home: input.home.clone(),
            ..Input::default()
        })?
    } else {
        validation::resolve_workspace_with_home(&input.workspace, input.home.as_deref())?;
        let response = super::authority::evaluate(
            "prepare",
            &json!({"command":[argv[0],"-m","pytest"],
            "workspace":input.workspace,"cwd":input.cwd,"platform":input.platform,
            "home":input.home,"backend_executable":input.backend_executable,
            "search_path":input.search_path,"read_only_workspace":true}),
        );
        if let Some(value) = response.get("value") {
            value.clone()
        } else {
            return Err(RestrictedPytestError::new(
                response["reason_code"]
                    .as_str()
                    .unwrap_or(PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE),
                response["message"]
                    .as_str()
                    .unwrap_or("Native inline preparation is unavailable."),
            ));
        }
    };
    let mut command = vec![plan["executable"].as_str().unwrap().to_owned()];
    command.extend(runtime);
    command.extend_from_slice(&argv[index..]);
    plan["profile_version"] = json!(if node {
        "node-eval-readonly-v1"
    } else {
        "python-eval-readonly-v1"
    });
    plan["command"] = json!(command);
    Ok(plan)
}
