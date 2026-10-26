//! Native-owned execution of captured Bash. This is not a grant lookup.

use std::ffi::{OsStr, OsString};
use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use guard_contained_process::{
    deferred_output::DeferredOutput, CapturedOutput, Isolation, SourceLaunchGate,
};

use super::bash_capture::CapturedBash;

pub(crate) fn execute(
    captured: CapturedBash,
    deadline: Instant,
    cancel: &AtomicBool,
    gate: &mut dyn SourceLaunchGate,
) -> io::Result<CapturedOutput> {
    if captured
        .policy
        .as_ref()
        .is_none_or(|policy| policy.has_hard_deny())
        || !captured.interpreter.has_readonly_system_image()?
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let source = captured
        .graph
        .source_for_launch()
        .map_err(|_| io::ErrorKind::InvalidData)?
        .to_owned();
    let bootstrap =
        guard_command::bash_approval::delivery::acknowledged_bootstrap(source.len(), 0, 6)
            .map_err(|_| io::ErrorKind::InvalidData)?;
    let mut arguments = vec![
        "--noprofile".into(),
        "--norc".into(),
        "-c".into(),
        OsString::from(bootstrap),
    ];
    arguments.extend(captured.subject.argv.iter().map(OsString::from));
    let environment = captured
        .environment
        .iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<Vec<_>>();
    let mut outputs = Vec::new();
    if let Some(report) = &captured.report {
        outputs.push(DeferredOutput::new(
            report.directory.clone(),
            &report.leaf,
            !report.append,
        )?);
    }
    let profile = profile(&captured)?;
    let command = captured.interpreter.with_invocation(
        &arguments
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<&OsStr>>(),
        &environment,
    )?;
    let broker_ids = captured
        .graph
        .invocations
        .iter()
        .filter_map(|invocation| {
            invocation
                .broker_id
                .map(|id| (id, invocation.operation.pipeline_input))
        })
        .collect::<Vec<_>>();
    let mut isolation = Isolation {
        seatbelt: Some(profile),
        deferred_outputs: outputs,
        creation_mask: captured.subject.context.file_creation_mask,
        ..Isolation::default()
    };
    if broker_ids.is_empty() {
        return command.capture_acknowledged_source(
            source.as_bytes(),
            1024 * 1024,
            deadline,
            cancel,
            isolation,
            gate,
        );
    }
    let (child, owner) = super::bash_broker::pair()?;
    isolation.inherited_files.push(child);
    let commands = captured.brokered_commands;
    std::thread::scope(|scope| {
        let broker = scope.spawn(move || {
            super::bash_broker::serve(owner, broker_ids, commands, deadline, cancel)
        });
        let output = command.capture_acknowledged_source(
            source.as_bytes(),
            1024 * 1024,
            deadline,
            cancel,
            isolation,
            gate,
        );
        let broker = broker
            .join()
            .map_err(|_| io::Error::other("compiled-image broker panicked"))?;
        broker?;
        output
    })
}

pub(super) fn profile(captured: &CapturedBash) -> io::Result<String> {
    let literal = |value: &str| serde_json::to_string(value).map_err(io::Error::other);
    let mut executables = vec![captured
        .interpreter
        .effective_executable_path()
        .to_str()
        .ok_or(io::ErrorKind::InvalidData)?
        .to_owned()];
    executables.extend(captured.graph.native_images.keys().cloned());
    let executables = executables
        .iter()
        .map(|path| literal(path).map(|path| format!("(literal {path})")))
        .collect::<io::Result<Vec<_>>>()?
        .join(" ");
    let outputs = captured
        .subject
        .outputs
        .iter()
        .map(|output| literal(&output.resolved_path).map(|path| format!("(literal {path})")))
        .collect::<io::Result<Vec<_>>>()?
        .join(" ");
    // macOS getcwd requires directory-data access as well as metadata. A
    // literal directory allows that lookup without allowing child file data.
    let cwd = literal(&captured.subject.context.cwd)?;
    let network = super::bash_network::rules(&captured.network_destinations);
    Ok(format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork)
(allow process-exec {executables})
(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share/locale") (subpath "/dev") {executables})
(allow file-read-metadata)
(allow file-read-data (literal {cwd}))
(allow file-map-executable (subpath "/System") (subpath "/usr/lib") {executables})
(allow file-write* (literal "/dev/null") {outputs})
{network}
(allow sysctl-read)
(allow mach-lookup)"#
    ))
}
