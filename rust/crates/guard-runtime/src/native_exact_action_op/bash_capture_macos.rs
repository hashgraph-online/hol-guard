//! Capture bytes through held filesystem handles; require system-root images.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
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
#[path = "bash_capture_cache_tests.rs"]
mod cache_tests;
#[cfg(test)]
#[path = "bash_grant_tests.rs"]
mod grant_tests;
#[cfg(test)]
#[path = "bash_launch_tests.rs"]
mod launch_tests;
#[cfg(test)]
#[path = "bash_network_tests.rs"]
mod network_tests;
#[cfg(test)]
#[path = "bash_package_binding_tests.rs"]
mod package_binding_tests;
#[cfg(test)]
#[path = "bash_policy_tests.rs"]
mod policy_tests;
#[cfg(test)]
#[path = "bash_capture_tests.rs"]
mod tests;

#[path = "bash_capture_cache.rs"]
mod analysis_cache;
#[path = "bash_capture_native.rs"]
mod native_image;
#[path = "bash_capture_outputs.rs"]
mod output_capture;
#[path = "bash_package_bindings.rs"]
mod package_bindings;
#[path = "bash_capture_paths.rs"]
mod paths;
#[path = "bash_capture_environment.rs"]
mod startup_environment;
#[cfg(test)]
use super::capture_for_launch;
use paths::{canonical, text};
use startup_environment::capture as environment;
type Result<T> = std::result::Result<T, &'static str>;

struct Resolver<'a> {
    cwd: &'a Path,
    home: &'a Path,
    environment: &'a BTreeMap<String, String>,
    names: &'a [String],
    deadline: Instant,
    captured: RefCell<BTreeMap<(String, PathBuf), graph::Executable>>,
    brokered_commands: RefCell<Vec<PinnedCommand>>,
    source_snapshots: RefCell<BTreeMap<(String, PathBuf), graph::Code>>,
    source_contents: RefCell<BTreeMap<PathBuf, Arc<str>>>,
    network_destinations: RefCell<BTreeSet<std::net::SocketAddrV4>>,
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
        startup_environment::reject_function(self.names, command)
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
            Some("/usr/bin/curl") => {
                let peers = super::super::bash_network::destinations(
                    argv, self.names, self.cwd, self.home,
                )?;
                self.network_destinations.borrow_mut().extend(peers);
                true
            }
            Some("/usr/bin/sort") => argv.len() == 1,
            Some("/usr/bin/base64") => argv.len() == 1,
            Some("/usr/bin/head") => {
                argv.len() == 3
                    && argv[1] == "-n"
                    && argv[2]
                        .parse::<u32>()
                        .is_ok_and(|count| count > 0 && count <= 10_000)
            }
            _ => false,
        };
        if matches!(
            path.to_str(),
            Some("/usr/bin/sort" | "/usr/bin/base64" | "/usr/bin/head")
        ) && !native
        {
            return Err("bash_native_arguments_unproven");
        }
        if let Some(captured) = self.captured.borrow().get(&key) {
            if matches!(
                captured,
                graph::Executable::Native {
                    delivery: graph::NativeDelivery::HardenedBroker,
                    ..
                }
            ) {
                // The final, output-bound graph pass must use the identity of
                // the exact private image it will launch. Reusing the observed
                // pass's digest would misbind a replacement between passes.
                let (current, command) = native_image::capture_hardened(self, &path, argv)?;
                self.brokered_commands.borrow_mut().push(command);
                return Ok(current);
            }
            return Ok(captured.clone());
        }
        if self.captured.borrow().len() >= 64 {
            return Err("bash_graph_bounds");
        }
        let captured = if native {
            native_image::capture(self, &path)?
        } else if let Ok((captured, command)) = native_image::capture_hardened(self, &path, argv) {
            self.brokered_commands.borrow_mut().push(command);
            captured
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

pub(crate) struct CapturedReport {
    pub(crate) directory: Arc<Directory>,
    pub(crate) leaf: OsString,
    pub(crate) append: bool,
}

/// Constructed only from native observations, never from a serialized subject.
pub(crate) struct CapturedBash {
    pub(crate) subject: NativeBashSubjectV1,
    pub(crate) graph: graph::Graph,
    pub(crate) interpreter: PinnedCommand,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) report: Option<CapturedReport>,
    pub(crate) policy: Option<super::super::bash_policy::Assessment>,
    pub(crate) network_destinations: BTreeSet<std::net::SocketAddrV4>,
    pub(crate) brokered_commands: Vec<PinnedCommand>,
}

pub(super) fn inspect(request: &NativeBashCaptureV1) -> Result<NativeBashSubjectV1> {
    capture(request, false).map(|captured| captured.subject)
}

pub(super) fn capture(request: &NativeBashCaptureV1, bind_outputs: bool) -> Result<CapturedBash> {
    // Resource deadline, not the separately measured installed-latency gate.
    let deadline = Instant::now()
        + Duration::from_millis(request.budget_ms.min(super::ANALYSIS_BUDGET_CAP_MS));
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
        brokered_commands: RefCell::new(Vec::new()),
        source_snapshots: RefCell::new(BTreeMap::new()),
        source_contents: RefCell::new(BTreeMap::new()),
        network_destinations: RefCell::new(BTreeSet::new()),
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
    let argv = &segment.arguments;
    if argv.is_empty() || argv[0].starts_with('-') || argv[0].starts_with('+') {
        return Err("bash_invocation_options_unproven");
    }
    let image = resolver.image(&interpreter)?;
    let cache_key = bind_outputs.then(|| analysis_cache::key(request)).flatten();
    let cached_graph = cache_key
        .as_ref()
        .and_then(|key| analysis_cache::reuse(key, &resolver, argv));
    let cache_hit = cached_graph.is_some();
    let graph = if let Some(graph) = cached_graph {
        graph
    } else {
        let entry = canonical(&text(&cwd.join(&argv[0]))?)?;
        let entry = resolver.code(&argv[0], &entry)?;
        let observed = graph::build(entry.clone(), argv, &environment, &resolver, deadline)
            .map_err(|uncertainty| uncertainty.reason)?;
        if bind_outputs {
            resolver.brokered_commands.borrow_mut().clear();
            let first_output = if observed.brokered_images.is_empty() {
                7
            } else {
                8
            };
            let fds = observed
                .writes
                .iter()
                .map(|effect| effect.redirect.path.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .enumerate()
                .map(|(index, path)| (path, first_output + index as u32))
                .collect();
            if observed.brokered_images.is_empty() {
                graph::build_with_acknowledged_outputs(
                    entry,
                    argv,
                    &environment,
                    &resolver,
                    deadline,
                    &fds,
                )
            } else {
                graph::build_with_acknowledged_broker_outputs(
                    entry,
                    argv,
                    &environment,
                    &resolver,
                    deadline,
                    &fds,
                )
            }
            .map_err(|uncertainty| uncertainty.reason)?
        } else {
            observed
        }
    };
    // Bash 3 exports functions under the command name; Bash 4+ encodes it.
    // A withheld function body must not be mistaken for a PATH executable or builtin.
    for call in &graph.invocations {
        resolver.check()?;
        resolver.reject_function(&call.operation.argv[0])?;
    }
    let (outputs, report) =
        output_capture::capture(&graph, &resolver, &cwd, &guard_home, bind_outputs)?;
    resolver.check()?;
    let mut subject = subject::from_graph(
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
                content_sha256: image.executable_digest.clone(),
            },
            environment: &environment,
            resolved_outputs: &outputs,
        },
    )?;
    subject.package_bindings =
        package_bindings::observe(&subject, graph.frozen_source_bytes(), deadline);
    subject.validate()?;
    resolver.check()?;
    let network_destinations = resolver.network_destinations.into_inner();
    let brokered_commands = resolver.brokered_commands.into_inner();
    if brokered_commands.len()
        != graph
            .invocations
            .iter()
            .filter(|invocation| invocation.broker_id.is_some())
            .count()
    {
        return Err("bash_broker_capture_mismatch");
    }
    let captured = CapturedBash {
        subject,
        graph,
        interpreter: image,
        environment,
        report,
        policy: None,
        network_destinations,
        brokered_commands,
    };
    if !cache_hit {
        if let Some(key) = cache_key {
            analysis_cache::insert(key, &captured.graph);
        }
    }
    Ok(captured)
}
