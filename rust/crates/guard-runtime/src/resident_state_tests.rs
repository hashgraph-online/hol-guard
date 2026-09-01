use super::*;

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
#[cfg(unix)]
use nix::unistd::Pid as UnixPid;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

fn process_is_alive(process_id: u32) -> bool {
    if process_id == 0 {
        return false;
    }
    #[cfg(unix)]
    if let Some(alive) = wait_for_owned_process(process_id) {
        return alive;
    }
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system
        .process(pid)
        .is_some_and(|process| !super::process_is_terminal(process.status()))
}

#[cfg(unix)]
fn wait_for_owned_process(process_id: u32) -> Option<bool> {
    let process_id = i32::try_from(process_id).ok()?;
    match waitpid(UnixPid::from_raw(process_id), Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => Some(true),
        Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _)) => Some(false),
        Ok(_) => Some(true),
        Err(Errno::ECHILD | Errno::ESRCH) => None,
        Err(_) => None,
    }
}

fn test_scope(label: &str) -> PathBuf {
    let unique = format!(
        "hol-guard-resident-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    );
    let path = std::env::temp_dir().join(unique);
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn state_mac_rejects_endpoint_mutation() {
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    let digest = runtime_digest().unwrap();
    let mut state = ResidentState {
        schema: STATE_SCHEMA.to_owned(),
        generation: 1,
        process_id: 1,
        process_start_marker: "linux:1".to_owned(),
        owner_process_id: 1,
        owner_process_start_marker: "linux:1".to_owned(),
        runtime_sha256: digest,
        transport: "loopback".to_owned(),
        endpoint: "127.0.0.1:1234".to_owned(),
        token_hex: hex_bytes(&token),
        created_ms: 1,
        state_mac: String::new(),
    };
    state.state_mac = state_mac(&state, &token);
    state.endpoint = "127.0.0.1:4321".to_owned();
    assert_ne!(state.state_mac, state_mac(&state, &token));
}

#[test]
fn process_identity_rejects_a_reused_same_binary_pid_marker() {
    let process_id = std::process::id();
    let marker = process_start_marker(process_id).unwrap();
    assert!(validate_package_process_identity(process_id, &marker).is_ok());
    assert!(validate_package_process_identity(process_id, "stale-process-start-marker").is_err());
}

#[test]
fn publishing_generations_retires_superseded_state() {
    let scope = test_scope("state-retention");
    let digest = runtime_digest().unwrap();
    let token = [7u8; crate::AUTH_TOKEN_BYTES];
    for generation in 1..=70 {
        publish_state(
            &scope,
            generation,
            std::process::id(),
            &digest,
            "loopback",
            "127.0.0.1:1".to_owned(),
            &token,
        )
        .unwrap();
    }
    let states = discover_states(&scope, &digest).unwrap();
    assert_eq!(states.len(), RETAINED_STATE_FILES);
    assert_eq!(states[0].generation, 70);
    assert_eq!(states.last().unwrap().generation, 63);
    fs::remove_dir_all(scope).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn process_start_marker_uses_darwin_native_start_time() {
    let marker = process_start_marker(std::process::id()).unwrap();
    let mut parts = marker.split(':');
    assert_eq!(parts.next(), Some("darwin"));
    assert!(parts
        .next()
        .is_some_and(|value| value.parse::<u64>().is_ok()));
    assert!(parts
        .next()
        .is_some_and(|value| value.parse::<u32>().is_ok()));
    assert!(parts.next().is_none());
}

#[cfg(unix)]
#[test]
fn process_is_alive_reaps_an_unreaped_child() {
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let process_id = child.id();
    let mut contained = false;
    for _ in 0..200 {
        if !process_is_alive(process_id) {
            contained = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(contained, "terminated child remained live");
    assert!(
        child.wait().is_err(),
        "process_is_alive did not reap the child"
    );
}

#[cfg(windows)]
#[test]
fn windows_state_scope_and_token_state_are_owner_private() {
    let base = test_scope("windows-private-state");
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&base, &digest).unwrap();
    let token = [9u8; crate::AUTH_TOKEN_BYTES];
    publish_state(
        &scope,
        1,
        std::process::id(),
        &digest,
        "loopback",
        "127.0.0.1:1".to_owned(),
        &token,
    )
    .unwrap();
    assert_eq!(discover_states(&scope, &digest).unwrap().len(), 1);
    fs::remove_dir_all(base).unwrap();
}
