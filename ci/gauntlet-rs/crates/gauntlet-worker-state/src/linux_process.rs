//! Linux pidfd, `/proc` start-tick and cgroup observation. No candidate code
//! is imported or executed; a failed sample is unavailable, never zero usage.

#[cfg(target_os = "linux")]
use rustix::event::{poll, PollFd, PollFlags, Timespec};
#[cfg(target_os = "linux")]
use rustix::fs::{open, openat, Mode, OFlags};
#[cfg(target_os = "linux")]
use rustix::process::{pidfd_open, Pid, PidfdFlags};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

const MAX_PROC_BYTES: usize = 4096;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessObservationError {
    InvalidExpectation,
    Unavailable,
    IdentityMismatch,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub pid: u32,
    pub start_ticks: u64,
    pub state: char,
    pub rss_pages: i64,
    pub cgroup: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcStat {
    pub(crate) start_ticks: u64,
    pub(crate) parent_pid: u32,
    pub(crate) state: char,
    rss_pages: i64,
}

pub(crate) fn parse_proc_stat(raw: &[u8], expected_pid: u32) -> Option<ProcStat> {
    if raw.len() > MAX_PROC_BYTES {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    let (prefix, tail) = text.rsplit_once(')')?;
    let (pid, _) = prefix.split_once(" (")?;
    if pid.parse::<u32>().ok()? != expected_pid {
        return None;
    }
    let fields: Vec<_> = tail.split_whitespace().collect();
    if fields.len() < 22 || fields[0].len() != 1 {
        return None;
    }
    let state = fields[0].chars().next()?;
    let parent_pid = fields[1].parse::<u32>().ok()?;
    let start_ticks = fields[19].parse::<u64>().ok().filter(|ticks| *ticks > 0)?;
    let rss_pages = fields[21].parse::<i64>().ok().filter(|pages| *pages >= 0)?;
    Some(ProcStat {
        start_ticks,
        parent_pid,
        state,
        rss_pages,
    })
}

pub(crate) fn valid_cgroup(path: &str) -> bool {
    path.len() <= 256
        && path.starts_with('/')
        && path != "/"
        && path[1..].split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn cgroup_matches(raw: &[u8], expected: &str) -> bool {
    if raw.len() > MAX_PROC_BYTES || !valid_cgroup(expected) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let mut unified = text.lines().filter(|line| line.starts_with("0::"));
    unified.next() == Some(format!("0::{expected}").as_str()) && unified.next().is_none()
}

#[cfg(target_os = "linux")]
fn read_proc_file(directory: &OwnedFd, name: &str) -> Result<Vec<u8>, ProcessObservationError> {
    let descriptor = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let mut raw = Vec::new();
    File::from(descriptor)
        .take((MAX_PROC_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ProcessObservationError::Unavailable)?;
    if raw.len() > MAX_PROC_BYTES {
        return Err(ProcessObservationError::Unavailable);
    }
    Ok(raw)
}

/// Pin a Linux process with pidfd while sampling its start tick and unified
/// cgroup twice. The expected cgroup and start tick must come from outside the
/// candidate. Zombies, exited pidfds and changed samples are not live proof.
#[cfg(target_os = "linux")]
pub fn observe_process(
    pid: u32,
    expected_start_ticks: u64,
    expected_cgroup: &str,
) -> Result<ProcessObservation, ProcessObservationError> {
    let raw_pid = i32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(ProcessObservationError::InvalidExpectation)?;
    if expected_start_ticks == 0 || !valid_cgroup(expected_cgroup) {
        return Err(ProcessObservationError::InvalidExpectation);
    }
    let pidfd = pidfd_open(
        Pid::from_raw(raw_pid).ok_or(ProcessObservationError::InvalidExpectation)?,
        PidfdFlags::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let proc = open(
        "/proc",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let directory = openat(
        &proc,
        pid.to_string(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProcessObservationError::Unavailable)?;
    let first = parse_proc_stat(&read_proc_file(&directory, "stat")?, pid)
        .ok_or(ProcessObservationError::Unavailable)?;
    let cgroup_before = read_proc_file(&directory, "cgroup")?;
    let second = parse_proc_stat(&read_proc_file(&directory, "stat")?, pid)
        .ok_or(ProcessObservationError::Unavailable)?;
    let cgroup_after = read_proc_file(&directory, "cgroup")?;
    if first.start_ticks != expected_start_ticks
        || second.start_ticks != expected_start_ticks
        || !matches!(second.state, 'R' | 'S' | 'D')
        || cgroup_before != cgroup_after
        || !cgroup_matches(&cgroup_after, expected_cgroup)
    {
        return Err(ProcessObservationError::IdentityMismatch);
    }
    let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
    let immediate = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if poll(&mut descriptors, Some(&immediate)).map_err(|_| ProcessObservationError::Unavailable)?
        != 0
    {
        return Err(ProcessObservationError::Unavailable);
    }
    Ok(ProcessObservation {
        pid,
        start_ticks: second.start_ticks,
        state: second.state,
        rss_pages: second.rss_pages,
        cgroup: expected_cgroup.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pid: u32, state: &str, ticks: &str) -> String {
        let mut fields: Vec<String> = (0..22).map(|index| index.to_string()).collect();
        fields[0] = state.to_owned();
        fields[19] = ticks.to_owned();
        fields[21] = "7".to_owned();
        format!("{pid} (worker) odd) name) {}", fields.join(" "))
    }

    #[test]
    fn parses_start_tick_after_the_last_parenthesis_and_refuses_pid_reuse() {
        let row = stat(42, "S", "1234567");
        let parsed = parse_proc_stat(row.as_bytes(), 42).unwrap();
        assert_eq!(parsed.start_ticks, 1_234_567);
        assert_eq!(parsed.parent_pid, 1);
        assert_eq!(parsed.rss_pages, 7);
        assert!(parse_proc_stat(row.as_bytes(), 43).is_none());
        assert!(parse_proc_stat(stat(42, "S", "0").as_bytes(), 42).is_none());
    }

    #[test]
    fn unified_cgroup_must_match_one_canonical_outside_path() {
        assert!(cgroup_matches(
            b"0::/system.slice/hol-product-cell-abc.service\n",
            "/system.slice/hol-product-cell-abc.service"
        ));
        assert!(!cgroup_matches(
            b"0::/system.slice/other.service\n",
            "/system.slice/hol-product-cell-abc.service"
        ));
        assert!(!cgroup_matches(
            b"0::/system.slice/hol-product-cell-abc.service\n0::/system.slice/hol-product-cell-abc.service\n",
            "/system.slice/hol-product-cell-abc.service"
        ));
        assert!(!valid_cgroup("/system.slice/../other"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observes_own_pidfd_start_tick_and_cgroup_without_guessing() {
        let pid = std::process::id();
        let stat = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
        let expected = parse_proc_stat(&stat, pid).unwrap();
        let cgroup = std::fs::read(format!("/proc/{pid}/cgroup")).unwrap();
        let path = std::str::from_utf8(&cgroup)
            .unwrap()
            .trim_end()
            .strip_prefix("0::")
            .unwrap();
        assert!(valid_cgroup(path));
        let sample = observe_process(pid, expected.start_ticks, path).unwrap();
        assert_eq!(sample.pid, pid);
        assert_eq!(sample.start_ticks, expected.start_ticks);
        assert_eq!(sample.cgroup, path);
        assert_eq!(
            observe_process(pid, expected.start_ticks + 1, path),
            Err(ProcessObservationError::IdentityMismatch)
        );
        assert_eq!(
            observe_process(pid, expected.start_ticks, "/system.slice/not-this-process"),
            Err(ProcessObservationError::IdentityMismatch)
        );
    }
}
