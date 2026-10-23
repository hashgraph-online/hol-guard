//! Opt-in, single-session SDK MCP child. The pinned Root worker supplies its
//! held FDs; `pidns-connect` hands Native connection ownership back to Root.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use gauntlet_worker_state::{
    connect_native_once_pidns_ineligible, run_sdk_tap_child_once_ineligible,
    run_sdk_tap_child_once_pidns_ineligible, SdkTapChildPins, SdkWirePeerPin,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use std::os::unix::net::UnixStream;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn fd(value: &str) -> Result<RawFd, String> {
    let parsed = value
        .parse::<RawFd>()
        .map_err(|_| "invalid SDK tap child descriptor".to_owned())?;
    if !(3..=4096).contains(&parsed) {
        return Err("SDK tap child descriptor outside fixed range".to_owned());
    }
    Ok(parsed)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn pin(pid: &str, start: &str, cgroup: &str) -> Result<SdkWirePeerPin, String> {
    let pid = pid.parse::<u32>().map_err(|_| "invalid peer PID")?;
    let start_ticks = start.parse::<u64>().map_err(|_| "invalid peer start")?;
    if pid == 0 || start_ticks == 0 || cgroup.is_empty() || cgroup.len() > 4096 {
        return Err("SDK tap child peer pin outside fixed bounds".to_owned());
    }
    Ok(SdkWirePeerPin {
        pid,
        start_ticks,
        cgroup: cgroup.to_owned(),
    })
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|mode| matches!(mode.as_str(), "pidns" | "pidns-connect"))
    {
        if arguments.len() != 7 || !matches!(arguments[2].as_str(), "docs" | "mail") {
            return Err("fixed PID-namespace tap child arguments required".to_owned());
        }
        let client_fd = fd(&arguments[3])?;
        let directory_fd = fd(&arguments[4])?;
        let report_fd = fd(&arguments[5])?;
        let handoff_fd = fd(&arguments[6])?;
        if [client_fd, directory_fd, report_fd, handoff_fd]
            .iter()
            .enumerate()
            .any(|(index, value)| {
                [client_fd, directory_fd, report_fd, handoff_fd][index + 1..].contains(value)
            })
        {
            return Err("SDK tap child descriptors must be distinct".to_owned());
        }
        // SAFETY: the four inherited descriptors are distinct and adopted
        // once by the fixed child process after Root's namespace checks.
        let (client, directory, report, handoff) = unsafe {
            (
                UnixStream::from_raw_fd(client_fd),
                OwnedFd::from_raw_fd(directory_fd),
                UnixStream::from_raw_fd(report_fd),
                UnixStream::from_raw_fd(handoff_fd),
            )
        };
        if arguments[1] == "pidns-connect" {
            connect_native_once_pidns_ineligible(
                client,
                directory,
                report,
                handoff,
                &arguments[2],
            )?;
        } else {
            run_sdk_tap_child_once_pidns_ineligible(
                client,
                directory,
                report,
                handoff,
                &arguments[2],
            )?;
        }
        return Ok(());
    }
    if arguments.len() != 15 || !matches!(arguments[1].as_str(), "docs" | "mail") {
        return Err("fixed SDK tap child arguments required".to_owned());
    }
    let client_fd = fd(&arguments[2])?;
    let directory_fd = fd(&arguments[3])?;
    let report_fd = fd(&arguments[4])?;
    let handoff_fd = fd(&arguments[5])?;
    if client_fd == directory_fd
        || client_fd == report_fd
        || client_fd == handoff_fd
        || directory_fd == report_fd
        || directory_fd == handoff_fd
        || report_fd == handoff_fd
    {
        return Err("SDK tap child descriptors must be distinct".to_owned());
    }
    let sdk_relay = pin(&arguments[6], &arguments[7], &arguments[8])?;
    let sdk_ancestor = pin(&arguments[9], &arguments[10], &arguments[11])?;
    let native_frontdoor = pin(&arguments[12], &arguments[13], &arguments[14])?;
    // SAFETY: each distinct inherited FD was checked above and is adopted
    // exactly once; the worker must pass held Unix sockets and a directory.
    let (client, directory, report, handoff) = unsafe {
        (
            UnixStream::from_raw_fd(client_fd),
            OwnedFd::from_raw_fd(directory_fd),
            UnixStream::from_raw_fd(report_fd),
            UnixStream::from_raw_fd(handoff_fd),
        )
    };
    let pins = SdkTapChildPins {
        family: &arguments[1],
        sdk_relay: &sdk_relay,
        sdk_ancestor: &sdk_ancestor,
        native_frontdoor: &native_frontdoor,
    };
    run_sdk_tap_child_once_ineligible(client, directory, report, handoff, &pins)?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn main() {
    if let Err(error) = run() {
        eprintln!("SDK tap child ineligible: {error}");
        std::process::exit(2);
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn main() {
    eprintln!("SDK tap child requires Linux ARM64");
    std::process::exit(2);
}
