//! Capture bytes through held filesystem handles; require system-root images.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guard_command::bash_approval::{graph, subject, MAX_SOURCE_BYTES};
use guard_command::command_model::parse_shell_command;
use guard_command::secret_path_probe::is_request_secret_path;
use guard_contained_process::{bound_fs::Directory, PinnedCommand};
use guard_contracts::{
    NativeBashCaptureV1, NativeBashContextV1, NativeBashHostV1, NativeBashSubjectV1,
    NativeScriptCodeInputV1, NativeScriptInputKindV1,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "bash_capture_tests.rs"]
mod tests;

const SELECTED: &[&str] = &[
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_MONETARY",
    "TMPDIR",
];
type Result<T> = std::result::Result<T, &'static str>;

fn canonical(value: &str) -> Result<PathBuf> {
    if guard_command::bash_approval::is_descriptor_reference(value) {
        return Err("bash_process_descriptor_unproven");
    }
    if value.len() > 4096 || !Path::new(value).is_absolute() {
        return Err("bash_context_path_invalid");
    }
    std::fs::canonicalize(value).map_err(|_| "bash_context_path_unavailable")
}

fn text(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or("bash_path_encoding")
}

fn environment(request: &NativeBashCaptureV1) -> Result<BTreeMap<String, String>> {
    let stamp = &request.execution_environment;
    if !stamp.has_valid_shape() || stamp.home.as_deref() != Some(request.home_dir.as_str()) {
        return Err("bash_host_environment_unavailable");
    }
    for name in &stamp.environment_names {
        if matches!(
            name.as_str(),
            "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "POSIXLY_CORRECT" | "GLOBIGNORE"
        ) || name.starts_with("LD_")
            || name.starts_with("DYLD_")
            || name.starts_with("BASH_FUNC_")
            || name.starts_with("__BASH_FUNC")
        {
            return Err("bash_startup_environment_unproven");
        }
        if SELECTED.contains(&name.as_str()) && !request.environment.contains_key(name) {
            return Err("bash_host_environment_value_withheld");
        }
    }
    if request.environment.iter().any(|(name, value)| {
        !SELECTED.contains(&name.as_str())
            || value.len() > 32 * 1024
            || value.contains('\0')
            || !stamp.environment_names.contains(name)
    }) {
        return Err("bash_host_environment_invalid");
    }
    let mut environment = request.environment.clone();
    environment.insert("HOME".into(), request.home_dir.clone());
    environment.insert("PATH".into(), stamp.path.clone());
    if environment
        .values()
        .any(|value| value.trim_start().starts_with("()"))
    {
        return Err("bash_startup_environment_unproven");
    }
    Ok(environment)
}

struct Resolver<'a> {
    cwd: &'a Path,
    home: &'a Path,
    environment: &'a BTreeMap<String, String>,
    names: &'a [String],
    deadline: Instant,
    captured: RefCell<BTreeMap<(String, PathBuf), graph::Executable>>,
    source_snapshots: RefCell<BTreeMap<(String, PathBuf), graph::Code>>,
    source_contents: RefCell<BTreeMap<PathBuf, Arc<str>>>,
}

impl Resolver<'_> {
    fn check(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err("bash_analysis_timeout");
        }
        Ok(())
    }

    fn resolve_path(&self, executable: &str) -> Result<PathBuf> {
        self.resolve_spelling(executable).map(|(_, path)| path)
    }

    fn resolve_spelling(&self, executable: &str) -> Result<(String, PathBuf)> {
        self.check()?;
        self.reject_function(executable)?;
        if executable.is_empty() || executable.len() > 4096 {
            return Err("bash_helper_unresolved");
        }
        if self.environment["PATH"].split(':').count() > 256 {
            return Err("bash_path_search_bounds");
        }
        let candidates = if executable.contains('/') {
            vec![PathBuf::from(executable)]
        } else {
            self.environment["PATH"]
                .split(':')
                .map(|directory| {
                    let directory = if directory.is_empty() && !self.environment["PATH"].is_empty()
                    {
                        "."
                    } else {
                        directory
                    };
                    Path::new(directory).join(executable)
                })
                .collect()
        };
        for candidate in candidates {
            self.check()?;
            let observed_path = self.cwd.join(&candidate);
            let Ok(metadata) = std::fs::metadata(&observed_path) else {
                continue;
            };
            if metadata.is_file()
                && metadata.permissions().mode() & 0o111 != 0
                && guard_contained_process::bound_fs::can_execute(&observed_path)
                    .map_err(|_| "bash_helper_unresolved")?
            {
                let resolved =
                    std::fs::canonicalize(observed_path).map_err(|_| "bash_helper_unresolved")?;
                return Ok((text(&candidate)?, resolved));
            }
        }
        Err("bash_helper_unresolved")
    }

    fn reject_function(&self, command: &str) -> Result<()> {
        let encoded = format!("BASH_FUNC_{command}%%");
        let apple = format!("__BASH_FUNC<{command}>()");
        if self
            .names
            .iter()
            .any(|name| name == command || name == &encoded || name == &apple)
        {
            return Err("bash_command_environment_value_withheld");
        }
        Ok(())
    }

    fn code(&self, requested: &str, resolved: &Path) -> Result<graph::Code> {
        self.check()?;
        for candidate in [Path::new(requested), resolved] {
            if guard_command::bash_approval::is_descriptor_reference(&text(candidate)?) {
                return Err("bash_process_descriptor_unproven");
            }
            if is_request_secret_path(&text(candidate)?, Some(self.cwd), Some(self.home)) {
                return Err("bash_sensitive_code_path");
            }
        }
        if let Some(source) = self.source_contents.borrow().get(resolved).cloned() {
            return Ok(graph::Code {
                original_path: requested.into(),
                resolved_path: text(resolved)?,
                source,
            });
        }
        if self.source_contents.borrow().len() >= 64 {
            return Err("bash_source_graph_bounds");
        }
        let directory = Directory::open(resolved.parent().ok_or("bash_code_path_invalid")?)
            .map_err(|_| "bash_code_unreadable")?;
        let read = directory
            .read(
                Path::new(resolved.file_name().ok_or("bash_code_path_invalid")?),
                MAX_SOURCE_BYTES,
            )
            .map_err(|_| "bash_code_unreadable_or_oversized")?;
        self.check()?;
        let source: Arc<str> = String::from_utf8(read.bytes)
            .map_err(|_| "bash_code_encoding")?
            .into();
        self.source_contents
            .borrow_mut()
            .insert(resolved.to_owned(), source.clone());
        Ok(graph::Code {
            original_path: requested.into(),
            resolved_path: text(resolved)?,
            source,
        })
    }

    fn image(&self, path: &Path) -> Result<PinnedCommand> {
        self.check()?;
        let pinned = PinnedCommand::new(path, &[], self.cwd, &[])
            .map_err(|_| "bash_system_image_unavailable")?;
        if !pinned
            .has_readonly_system_image()
            .map_err(|_| "bash_system_image_unavailable")?
        {
            return Err("bash_system_image_not_immutable");
        }
        self.check()?;
        Ok(pinned)
    }
}

impl graph::Resolver for Resolver<'_> {
    fn environment_names(&self) -> &[String] {
        self.names
    }
    fn resolve_source(&self, path: &str) -> Result<graph::Code> {
        self.check()?;
        if path.is_empty() || path.len() > 4096 || self.environment["PATH"].split(':').count() > 256
        {
            return Err("bash_source_path_invalid");
        }
        let candidates = if path.contains('/') {
            vec![PathBuf::from(path)]
        } else {
            self.environment["PATH"]
                .split(':')
                .map(|directory| Path::new(directory).join(path))
                .chain(std::iter::once(PathBuf::from(path)))
                .collect()
        };
        for candidate in candidates {
            self.check()?;
            let observed = self.cwd.join(&candidate);
            if !std::fs::metadata(&observed).is_ok_and(|metadata| metadata.is_file()) {
                continue;
            }
            let resolved = std::fs::canonicalize(observed).map_err(|_| "bash_source_unresolved")?;
            let spelling = text(&candidate)?;
            let key = (spelling.clone(), resolved.clone());
            if let Some(code) = self.source_snapshots.borrow().get(&key) {
                return Ok(code.clone());
            }
            if self.source_snapshots.borrow().len() + self.captured.borrow().len() >= 64 {
                return Err("bash_source_graph_bounds");
            }
            let code = self.code(&spelling, &resolved)?;
            self.source_snapshots.borrow_mut().insert(key, code.clone());
            return Ok(code);
        }
        Err("bash_source_unresolved")
    }

    fn resolve(&self, argv: &[String]) -> Result<graph::Executable> {
        self.check()?;
        let (spelling, path) = self.resolve_spelling(&argv[0])?;
        let key = (spelling.clone(), path.clone());
        let native = match path.to_str() {
            Some("/usr/bin/sort") => argv.len() == 1,
            Some("/usr/bin/head") => {
                argv.len() == 3
                    && argv[1] == "-n"
                    && argv[2]
                        .parse::<u32>()
                        .is_ok_and(|count| count > 0 && count <= 10_000)
            }
            _ => false,
        };
        if matches!(path.to_str(), Some("/usr/bin/sort" | "/usr/bin/head")) && !native {
            return Err("bash_native_arguments_unproven");
        }
        if let Some(captured) = self.captured.borrow().get(&key) {
            return Ok(captured.clone());
        }
        if self.captured.borrow().len() >= 64 {
            return Err("bash_graph_bounds");
        }
        let captured = if native {
            let pinned = self.image(&path)?;
            graph::Executable::Native {
                resolved_path: text(&path)?,
                content_sha256: pinned.executable_digest,
            }
        } else {
            if spelling.starts_with('-') || spelling.starts_with('+') {
                return Err("bash_helper_interpreter_unproven");
            }
            let code = self.code(&spelling, &path)?;
            if code.source.split('\n').next() != Some("#!/bin/bash") {
                return Err("bash_helper_interpreter_unproven");
            }
            graph::Executable::Bash(code)
        };
        self.captured.borrow_mut().insert(key, captured.clone());
        Ok(captured)
    }
}

pub(super) fn inspect(request: &NativeBashCaptureV1) -> Result<NativeBashSubjectV1> {
    // Resource deadline, not the separately measured installed-latency gate.
    let deadline = Instant::now() + Duration::from_millis(request.budget_ms.min(1000));
    if request.file_creation_mask.is_some_and(|mask| mask > 0o777) {
        return Err("bash_host_creation_mask_invalid");
    }
    let host = match request.harness.as_str() {
        "omp" => NativeBashHostV1::OmpInputRewriteV1,
        "pi" => NativeBashHostV1::PiInputMutationV1,
        _ => return Err("bash_host_delivery_unavailable"),
    };
    let cwd = canonical(&request.cwd)?;
    let project = canonical(&request.workspace)?;
    let home = canonical(&request.home_dir)?;
    let guard_home = canonical(&request.guard_home)?;
    if !cwd.starts_with(&project) {
        return Err("bash_project_context_mismatch");
    }
    let environment = environment(request)?;
    let resolver = Resolver {
        cwd: &cwd,
        home: &home,
        environment: &environment,
        names: &request.execution_environment.environment_names,
        deadline,
        captured: RefCell::new(BTreeMap::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
        source_contents: RefCell::new(BTreeMap::new()),
    };
    let model = parse_shell_command(
        &request.command,
        Some(&cwd),
        Some(&home),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if !super::super::launch::is_safe_single_invocation(&model) {
        return Err("bash_invocation_unproven");
    }
    let segment = &model.segments[0];
    if segment
        .executable
        .as_deref()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        != Some("bash")
    {
        return Err("bash_interpreter_spelling_unproven");
    }
    let interpreter = resolver.resolve_path(
        segment
            .executable
            .as_deref()
            .ok_or("bash_interpreter_unavailable")?,
    )?;
    if interpreter != Path::new("/bin/bash") {
        return Err("bash_interpreter_unproven");
    }
    let image = resolver.image(&interpreter)?;
    let argv = &segment.arguments;
    if argv.is_empty() || argv[0].starts_with('-') || argv[0].starts_with('+') {
        return Err("bash_invocation_options_unproven");
    }
    let entry = canonical(&text(&cwd.join(&argv[0]))?)?;
    let graph = graph::build(
        resolver.code(&argv[0], &entry)?,
        argv,
        &environment,
        &resolver,
        deadline,
    )
    .map_err(|uncertainty| uncertainty.reason)?;
    // Bash 3 exports functions under the command name; Bash 4+ encodes it.
    // A withheld function body must not be mistaken for a PATH executable or builtin.
    for call in &graph.invocations {
        resolver.check()?;
        resolver.reject_function(&call.operation.argv[0])?;
    }
    let mut outputs = BTreeMap::new();
    for effect in &graph.writes {
        resolver.check()?;
        let leaf = effect.redirect.path.rsplit('/').next().unwrap_or("");
        if matches!(leaf, "" | "." | "..") {
            return Err("bash_output_path_invalid");
        }
        if guard_command::bash_approval::is_descriptor_reference(&effect.redirect.path) {
            return Err("bash_process_descriptor_unproven");
        }
        if outputs.contains_key(&effect.redirect.path) {
            continue;
        }
        let path = cwd.join(&effect.redirect.path);
        let parent = std::fs::canonicalize(path.parent().ok_or("bash_output_path_invalid")?)
            .map_err(|_| "bash_output_parent_unavailable")?;
        if guard_command::bash_approval::is_descriptor_reference(&text(&parent)?) {
            return Err("bash_process_descriptor_unproven");
        }
        let resolved = parent.join(path.file_name().ok_or("bash_output_path_invalid")?);
        if guard_command::bash_approval::is_descriptor_reference(&text(&resolved)?) {
            return Err("bash_process_descriptor_unproven");
        }
        let directory = Directory::open(&parent).map_err(|_| "bash_output_parent_unavailable")?;
        guard_contained_process::bound_output::validate_target(
            &directory,
            resolved.file_name().ok_or("bash_output_path_invalid")?,
        )
        .map_err(|_| "bash_output_target_unavailable")?;
        outputs.insert(effect.redirect.path.clone(), text(&resolved)?);
    }
    resolver.check()?;
    subject::from_graph(
        &graph,
        subject::Observations {
            context: NativeBashContextV1 {
                host,
                host_scope_digest: hex::encode(Sha256::digest(format!(
                    "guard-bash-host-v1:{}",
                    request.harness
                ))),
                guard_home_scope_digest: hex::encode(Sha256::digest(text(&guard_home)?.as_bytes())),
                project: text(&project)?,
                cwd: text(&cwd)?,
                home: text(&home)?,
                file_creation_mask: request.file_creation_mask,
            },
            argv,
            interpreter: NativeScriptCodeInputV1 {
                kind: NativeScriptInputKindV1::Interpreter,
                requested_path: text(&interpreter)?,
                resolved_path: text(&interpreter)?,
                content_sha256: image.executable_digest,
            },
            environment: &environment,
            resolved_outputs: &outputs,
        },
    )
}
