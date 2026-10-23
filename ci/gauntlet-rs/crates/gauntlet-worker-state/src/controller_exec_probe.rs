//! Fixed inert Root controller execution probe, kept separate from launch.

use super::{spawn_root_fd, ControllerExecError};
use crate::contained_probe::OwnedJobCgroup;
use crate::interpreter_exec::InterpreterExecError;
use crate::linux_process::{observe_process, parse_proc_stat};
use crate::process_reap::reap_probe_child_bounded;
use crate::{open_root_owned_public_directory, HeldInterpreter};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

const PROBE_JOB_ID: &str = "a1b2c3d4e5f60718";
const PROBE_CODE: &str = "import os,time;os.fork();time.sleep(5)";
const POLL: Duration = Duration::from_millis(20);
const WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootControllerProbeProof {
    pub cgroup: String,
    pub observed_tasks: u64,
    pub interpreter_sha256: String,
    pub pid: u32,
    pub start_ticks: u64,
}

impl RootControllerProbeProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-root-controller-exec-probe.v1",
            "job_id":PROBE_JOB_ID,
            "cgroup":self.cgroup,
            "observed_tasks":self.observed_tasks,
            "interpreter_sha256":self.interpreter_sha256,
            "pid":self.pid,
            "process_start_ticks":self.start_ticks,
            "root_uid_kernel_observed":true,
            "no_new_privileges_kernel_observed":true,
            "execveat_fd_bound":true,
            "resource_profile":{"memory_max":4294967296_u64,"pids_max":256,"cpu_max":"100000 100000"},
            "recursive_kill_written":true,
            "drained_observed":true,
            "cgroup_removed":true,
            "controller_executed":false,
            "benchmark_executed":false,
            "execution_eligible":false,
        })
    }
}

fn observe_root_probe_child(pid: u32, cgroup: &str) -> Result<u64, ControllerExecError> {
    let stat = std::fs::read(format!("/proc/{pid}/stat"))
        .map_err(|_| ControllerExecError::ChildIdentityUnknown)?;
    let ticks = parse_proc_stat(&stat, pid)
        .ok_or(ControllerExecError::ChildIdentityUnknown)?
        .start_ticks;
    observe_process(pid, ticks, cgroup).map_err(ControllerExecError::Process)?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| ControllerExecError::ChildIdentityUnknown)?;
    let uid = status.lines().find(|line| line.starts_with("Uid:"));
    let no_new_privs = status.lines().find(|line| line.starts_with("NoNewPrivs:"));
    if uid.map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
        != Some(vec!["Uid:", "0", "0", "0", "0"])
        || no_new_privs.map(|line| line.split_ascii_whitespace().collect::<Vec<_>>())
            != Some(vec!["NoNewPrivs:", "1"])
    {
        return Err(ControllerExecError::ChildIdentityUnknown);
    }
    observe_process(pid, ticks, cgroup).map_err(ControllerExecError::Process)?;
    Ok(ticks)
}

/// Fixed inert proof of the same Root `execveat` syscall path that a future
/// prepared controller will use. It does not import any controller code.
pub fn run_fixed_root_controller_exec_probe(
    interpreter: &HeldInterpreter,
) -> Result<RootControllerProbeProof, ControllerExecError> {
    if geteuid().as_raw() != 0 {
        return Err(ControllerExecError::RootRequired);
    }
    let mut group = OwnedJobCgroup::create(PROBE_JOB_ID).map_err(ControllerExecError::Cgroup)?;
    let cgroup = group.path().to_owned();
    let argv = vec![
        interpreter.declaration().python_path.clone(),
        "-I".to_owned(),
        "-S".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        PROBE_CODE.to_owned(),
    ];
    let environment = BTreeMap::from([
        ("PATH", "/usr/bin:/bin".to_owned()),
        ("LANG", "C.UTF-8".to_owned()),
        ("HOME", "/root".to_owned()),
        (
            "HOL_GAUNTLET_RUST_JOB_SLICE",
            format!("holgauntletrust{PROBE_JOB_ID}.slice"),
        ),
    ]);
    let cwd = match open_root_owned_public_directory(Path::new("/")) {
        Ok(cwd) => cwd,
        Err(_) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(ControllerExecError::InvalidPlan);
        }
    };
    let writer = match group.writer() {
        Ok(writer) => writer,
        Err(error) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(ControllerExecError::Cgroup(error));
        }
    };
    let mut child = match spawn_root_fd(
        interpreter,
        &argv,
        &environment,
        cwd,
        writer,
        None,
        Stdio::null(),
        Stdio::null(),
    ) {
        Ok(child) => child,
        Err(error) => {
            group
                .drain_and_remove()
                .map_err(ControllerExecError::Cgroup)?;
            return Err(error);
        }
    };
    let started = Instant::now();
    let observed_tasks = loop {
        match group.tasks() {
            Ok(tasks) if tasks >= 2 => break Ok(tasks),
            Ok(_) if started.elapsed() < WAIT => thread::sleep(POLL),
            Ok(_) => break Err(ControllerExecError::ChildIdentityUnknown),
            Err(error) => break Err(ControllerExecError::Cgroup(error)),
        }
    };
    let identity = observe_root_probe_child(child.id(), &cgroup);
    let killed = group.kill().map_err(ControllerExecError::Cgroup);
    let reaped = reap_probe_child_bounded(&mut child).map_err(ControllerExecError::Cgroup);
    let drained = group
        .drain_and_remove()
        .map_err(ControllerExecError::Cgroup);
    let interpreter_unchanged = interpreter
        .assert_unchanged()
        .map_err(|_| ControllerExecError::Interpreter(InterpreterExecError::InvalidInterpreter));
    let observed_tasks = observed_tasks?;
    let start_ticks = identity?;
    killed?;
    reaped?;
    drained?;
    interpreter_unchanged?;
    Ok(RootControllerProbeProof {
        cgroup,
        observed_tasks,
        interpreter_sha256: interpreter.declaration().sha256.clone(),
        pid: child.id(),
        start_ticks,
    })
}
