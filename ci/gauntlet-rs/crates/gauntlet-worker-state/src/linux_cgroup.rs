//! Bounded cgroup-v2 resource sampling tied to a live pidfd observation.
//! Missing or malformed kernel counters are unavailable, never zero.

use crate::linux_process::{
    observe_process, valid_cgroup, ProcessObservation, ProcessObservationError,
};
use rustix::fs::{fstat, open, openat, Mode, OFlags};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const MAX_COUNTER_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupResources {
    pub memory_bytes: u64,
    pub memory_limit_bytes: Option<u64>,
    pub peak_memory_bytes: u64,
    pub tasks: u64,
    pub task_limit: Option<u64>,
    pub oom_kills: u64,
    pub pid_limit_hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResourceObservation {
    pub process: ProcessObservation,
    pub resources: CgroupResources,
}

/// One kernel snapshot of an owned cgroup subtree. `Drained` is only a
/// terminal-cleanup input while the caller still owns the worker lease and
/// prevents new processes from entering the cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupDrainState {
    Drained,
    Populated,
}

fn read_counter_bounded(
    directory: &OwnedFd,
    name: &str,
) -> Result<Vec<u8>, ProcessObservationError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAX_COUNTER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcessObservationError::Unavailable)?;
    if bytes.len() > MAX_COUNTER_BYTES {
        return Err(ProcessObservationError::Unavailable);
    }
    Ok(bytes)
}

fn read_counter(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, ProcessObservationError> {
    let bytes = read_counter_bounded(directory, name)?;
    if bytes.is_empty() {
        return Err(ProcessObservationError::Unavailable);
    }
    Ok(bytes)
}

fn parse_number(raw: &[u8], allow_max: bool) -> Option<Option<u64>> {
    let text = std::str::from_utf8(raw).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if allow_max && text == "max" {
        return Some(None);
    }
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(Some(text.parse().ok()?))
}

fn parse_event(raw: &[u8], target: &str) -> Option<u64> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut events = BTreeMap::new();
    for line in text.lines() {
        if events.len() >= 32 {
            return None;
        }
        let (name, count) = line.split_once(' ')?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return None;
        }
        let count = parse_number(count.as_bytes(), false)??;
        if events.insert(name, count).is_some() {
            return None;
        }
    }
    events.get(target).copied()
}

fn required_number(directory: &OwnedFd, name: &str) -> Result<u64, ProcessObservationError> {
    parse_number(&read_counter(directory, name)?, false)
        .flatten()
        .ok_or(ProcessObservationError::Unavailable)
}

fn limit(directory: &OwnedFd, name: &str) -> Result<Option<u64>, ProcessObservationError> {
    parse_number(&read_counter(directory, name)?, true).ok_or(ProcessObservationError::Unavailable)
}

fn event(directory: &OwnedFd, name: &str, target: &str) -> Result<u64, ProcessObservationError> {
    parse_event(&read_counter(directory, name)?, target).ok_or(ProcessObservationError::Unavailable)
}

fn cgroup_directory(path: &str) -> Result<OwnedFd, ProcessObservationError> {
    if !valid_cgroup(path) {
        return Err(ProcessObservationError::InvalidExpectation);
    }
    let mut directory = open(
        "/sys/fs/cgroup",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    for part in path[1..].split('/') {
        directory = openat(
            &directory,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ProcessObservationError::Unavailable)?;
    }
    Ok(directory)
}

fn classify_drain(
    before_events: u64,
    before_tasks: u64,
    direct_processes: &[u8],
    after_events: u64,
    after_tasks: u64,
) -> Result<CgroupDrainState, ProcessObservationError> {
    if before_events > 1 || after_events > 1 {
        return Err(ProcessObservationError::Unavailable);
    }
    if before_events == 0
        && after_events == 0
        && before_tasks == 0
        && after_tasks == 0
        && direct_processes.is_empty()
    {
        Ok(CgroupDrainState::Drained)
    } else {
        Ok(CgroupDrainState::Populated)
    }
}

/// Observe whether a retained cgroup still contains a process anywhere in
/// its subtree. Missing or malformed kernel files are unavailable, never
/// interpreted as successful cleanup. Reopening the path detects a removed
/// or replaced cgroup while the two samples are taken.
pub fn observe_cgroup_drain(path: &str) -> Result<CgroupDrainState, ProcessObservationError> {
    let directory = cgroup_directory(path)?;
    let original = fstat(&directory).map_err(|_| ProcessObservationError::Unavailable)?;
    let before_events = event(&directory, "cgroup.events", "populated")?;
    let before_tasks = required_number(&directory, "pids.current")?;
    let direct_processes = read_counter_bounded(&directory, "cgroup.procs")?;
    let after_events = event(&directory, "cgroup.events", "populated")?;
    let after_tasks = required_number(&directory, "pids.current")?;
    let reopened = cgroup_directory(path)?;
    let current = fstat(&reopened).map_err(|_| ProcessObservationError::Unavailable)?;
    if original.st_dev != current.st_dev || original.st_ino != current.st_ino {
        return Err(ProcessObservationError::Unavailable);
    }
    classify_drain(
        before_events,
        before_tasks,
        &direct_processes,
        after_events,
        after_tasks,
    )
}

fn read_resources(path: &str) -> Result<CgroupResources, ProcessObservationError> {
    let directory = cgroup_directory(path)?;
    Ok(CgroupResources {
        memory_bytes: required_number(&directory, "memory.current")?,
        memory_limit_bytes: limit(&directory, "memory.max")?,
        peak_memory_bytes: required_number(&directory, "memory.peak")?,
        tasks: required_number(&directory, "pids.current")?,
        task_limit: limit(&directory, "pids.max")?,
        oom_kills: event(&directory, "memory.events", "oom_kill")?,
        pid_limit_hits: event(&directory, "pids.events", "max")?,
    })
}

/// Sample kernel resource counters only while a process still has the
/// independently expected PID start tick and cgroup. The two process samples
/// bracket the cgroup reads; a missing counter makes the entire sample
/// unavailable. This reports a snapshot, not descendant cleanup or a verdict.
pub fn observe_process_resources(
    pid: u32,
    expected_start_ticks: u64,
    expected_cgroup: &str,
) -> Result<ProcessResourceObservation, ProcessObservationError> {
    observe_process(pid, expected_start_ticks, expected_cgroup)?;
    let resources = read_resources(expected_cgroup)?;
    let process = observe_process(pid, expected_start_ticks, expected_cgroup)?;
    Ok(ProcessResourceObservation { process, resources })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_limits_and_refuses_missing_or_forged_events() {
        assert_eq!(parse_number(b"max\n", true), Some(None));
        assert_eq!(parse_number(b"123\n", false), Some(Some(123)));
        assert_eq!(parse_number(b"-1\n", false), None);
        assert_eq!(parse_number(b"0\n1\n", false), None);
        assert_eq!(parse_event(b"low 0\noom_kill 2\n", "oom_kill"), Some(2));
        assert_eq!(parse_event(b"low 0\n", "oom_kill"), None);
        assert_eq!(parse_event(b"oom_kill 2\noom_kill 0\n", "oom_kill"), None);
        assert_eq!(
            parse_event(b"populated 0\nfrozen 0\n", "populated"),
            Some(0)
        );
        assert_eq!(parse_event(b"populated 1\n", "populated"), Some(1));
        assert_eq!(parse_event(b"frozen 0\n", "populated"), None);
        assert_eq!(
            classify_drain(0, 0, b"", 0, 0),
            Ok(CgroupDrainState::Drained)
        );
        assert_eq!(
            classify_drain(1, 0, b"", 0, 0),
            Ok(CgroupDrainState::Populated)
        );
        assert_eq!(
            classify_drain(0, 0, b"", 0, 1),
            Ok(CgroupDrainState::Populated)
        );
        assert_eq!(
            classify_drain(0, 0, b"123\n", 0, 0),
            Ok(CgroupDrainState::Populated)
        );
        assert_eq!(
            classify_drain(2, 0, b"", 0, 0),
            Err(ProcessObservationError::Unavailable)
        );
    }

    #[test]
    fn samples_own_cgroup_without_promoting_missing_counters_to_zero() {
        let pid = std::process::id();
        let stat = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
        let expected = crate::linux_process::parse_proc_stat(&stat, pid).unwrap();
        let cgroup = std::fs::read(format!("/proc/{pid}/cgroup")).unwrap();
        let path = std::str::from_utf8(&cgroup)
            .unwrap()
            .trim_end()
            .strip_prefix("0::")
            .unwrap();
        let sample = observe_process_resources(pid, expected.start_ticks, path).unwrap();
        assert_eq!(sample.process.cgroup, path);
        assert!(sample.resources.tasks > 0);
        assert!(sample.resources.peak_memory_bytes >= sample.resources.memory_bytes);
        assert_eq!(
            observe_process_resources(pid, expected.start_ticks, "/system.slice/absent.service"),
            Err(ProcessObservationError::IdentityMismatch)
        );
        assert_eq!(observe_cgroup_drain(path), Ok(CgroupDrainState::Populated));
        assert_eq!(
            observe_cgroup_drain("/system.slice/absent.service"),
            Err(ProcessObservationError::Unavailable)
        );
        assert_eq!(
            observe_cgroup_drain("/system.slice/../other"),
            Err(ProcessObservationError::InvalidExpectation)
        );
    }
}
