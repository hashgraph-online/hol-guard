//! The bounded spawn kernel: allowlisted environments, deadlines, output
//! bounds, process-group containment, the quarantine latch, and the Desktop hook
//! proxy that crosses into a contained environment.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn env() -> BTreeMap<String, String> {
    let mut e = BTreeMap::new();
    e.insert(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_default(),
    );
    e
}

fn tmp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("hps-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&p).unwrap();
    std::fs::canonicalize(&p).unwrap_or(p)
}

#[cfg(unix)]
#[test]
fn settling_the_quarantine_drains_a_contained_child_and_clears_the_latch() {
    let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
    let _ = child.wait();
    quarantine_child(child, Tree::default(), Arc::new(AtomicBool::new(true)));
    assert!(settle_quarantine(Duration::from_millis(500)));
    assert!(quarantine_lock().is_empty());
}

#[test]
fn environment_allowlist_filters() {
    let mut src = BTreeMap::new();
    src.insert("HOME".to_string(), "/u".to_string());
    src.insert("LC_ALL".to_string(), "C".to_string());
    src.insert("AWS_SECRET".to_string(), "x".to_string());
    src.insert("LD_PRELOAD".to_string(), "/e.so".to_string());
    src.insert("PATH".to_string(), "/bin".to_string());
    let e = isolated_hook_environment(&src);
    assert!(e.contains_key("HOME"));
    assert!(e.contains_key("LC_ALL"));
    let mut compiler = BTreeMap::new();
    compiler.insert(
        "HOL_GUARD_NATIVE_SOURCE_COMPILER".to_string(),
        "/c".to_string(),
    );
    compiler.insert(
        "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER".to_string(),
        "/c".to_string(),
    );
    compiler.insert("HOL_GUARD_RUNTIME_DIR".to_string(), "/r".to_string());
    let kept = isolated_hook_environment(&compiler);
    assert!(kept.contains_key("HOL_GUARD_NATIVE_SOURCE_COMPILER"));
    assert!(kept.contains_key("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"));
    assert!(!kept.contains_key("HOL_GUARD_RUNTIME_DIR"));
    assert!(e.contains_key("PATH"));
    assert!(!e.contains_key("AWS_SECRET"));
    assert!(!e.contains_key("LD_PRELOAD"));
}

#[cfg(unix)]
#[test]
fn runs_simple_command_to_completion() {
    let dir = tmp_dir("simple");
    let result = run_isolated_hook_process(
        &["/bin/echo".to_string(), "hello".to_string()],
        "",
        &dir,
        &env(),
        Some(5.0),
        Some(1024),
        None,
        None,
    );
    assert_eq!(result.returncode, Some(0));
    assert!(!result.timed_out);
    assert!(!result.containment_failed);
    assert!(result.stdout.trim().contains("hello"));
}

#[cfg(unix)]
#[test]
fn deadline_kills_long_running_process() {
    let dir = tmp_dir("timeout");
    let start = Instant::now();
    let result = run_isolated_hook_process(
        &["/bin/sleep".to_string(), "10".to_string()],
        "",
        &dir,
        &env(),
        Some(0.5),
        Some(1024),
        None,
        None,
    );
    let elapsed = start.elapsed();
    assert!(result.timed_out);
    assert!(elapsed < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn output_limit_marks_exceeded() {
    let dir = tmp_dir("limit");
    // Emit well over the limit.
    let result = run_isolated_hook_process(
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "head -c 20000 /dev/zero | tr '\\0' 'a'".to_string(),
        ],
        "",
        &dir,
        &env(),
        Some(5.0),
        Some(1024),
        None,
        None,
    );
    assert!(result.output_limit_exceeded);
}

#[cfg(unix)]
#[test]
fn process_group_kill_reaches_children() {
    // Spawn a shell that forks a grandchild; group kill must reap both.
    let dir = tmp_dir("group");
    let result = run_isolated_hook_process(
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep 30 & sleep 30".to_string(),
        ],
        "",
        &dir,
        &env(),
        Some(0.5),
        Some(1024),
        None,
        None,
    );
    assert!(result.timed_out);
}

#[cfg(unix)]
#[test]
fn stdin_input_reaches_child() {
    let dir = tmp_dir("stdin");
    let result = run_isolated_hook_process(
        &["/bin/cat".to_string()],
        "ping",
        &dir,
        &env(),
        Some(5.0),
        Some(1024),
        None,
        None,
    );
    assert_eq!(result.returncode, Some(0));
    assert!(result.stdout.contains("ping"));
}

#[test]
fn nonexistent_command_returns_null_resultcode() {
    let dir = tmp_dir("badcmd");
    let result = run_isolated_hook_process(
        &["/definitely/not/a/binary".to_string()],
        "",
        &dir,
        &env(),
        Some(1.0),
        Some(64),
        None,
        None,
    );
    assert_eq!(result.returncode, None);
    assert!(!result.containment_failed);
}

// World-writable rejection uses Unix mode bits. Windows has no 0o777
// equivalent in this helper, so the fixture cannot provoke the error.
#[cfg(unix)]
#[test]
fn private_runtime_cwd_rejects_world_writable_dir() {
    let dir = tmp_dir("cwdpub");
    // 0o777 parent → not owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    let manifest = dir.join("manifest.json");
    std::fs::write(&manifest, b"{}").unwrap();
    let r = private_hook_runtime_cwd(&manifest);
    assert!(r.is_err());
    // Restore for cleanup safety.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn guard_cli_command_pinned_bootstrap() {
    let cmd = isolated_guard_cli_command(
        "/usr/bin/python3",
        Path::new("/pkg/root"),
        &["guard".to_string(), "check".to_string()],
    );
    assert_eq!(cmd[0], "/usr/bin/python3");
    assert_eq!(cmd[1], "-I");
    assert_eq!(cmd[2], "-c");
    assert!(cmd[3].contains("codex_plugin_scanner.cli"));
    assert_eq!(cmd[4], "guard");
    assert_eq!(cmd[5], "check");
}

#[cfg(test)]
mod decode_bound_tests {
    use super::*;

    #[test]
    fn invalid_bytes_never_push_the_decoded_output_past_the_bound() {
        let stdout = vec![0xff_u8; 800];
        let stderr = vec![b'e'; 800];
        let (out, err) = decode_combined_output(&stdout, &stderr, 1024);
        assert!(out.len() + err.len() <= 1024);
        assert_eq!(out.len(), 1023);
        assert_eq!(err, "e");
    }

    #[test]
    fn a_character_split_by_the_cut_is_dropped_not_replaced() {
        assert_eq!(truncate_decoded("aé".to_owned(), 2), "a");
        assert_eq!(truncate_decoded("aé".to_owned(), 3), "aé");
        assert_eq!(truncate_decoded("abc".to_owned(), 0), "");
    }
}

#[cfg(test)]
mod desktop_proxy_tests {
    use super::*;

    fn source(proxy: &str, desktop: &str) -> BTreeMap<String, String> {
        let mut source = BTreeMap::new();
        source.insert("HOL_GUARD_DESKTOP".to_owned(), desktop.to_owned());
        source.insert("HOL_GUARD_DESKTOP_HOOK_PROXY".to_owned(), proxy.to_owned());
        source
    }

    #[test]
    fn the_desktop_proxy_crosses_only_when_signed_and_absolute() {
        let absolute = std::env::temp_dir()
            .join("proxy")
            .to_string_lossy()
            .into_owned();
        let kept = isolated_hook_environment(&source(&absolute, "1"));
        assert_eq!(kept.get("HOL_GUARD_DESKTOP").map(String::as_str), Some("1"));
        assert_eq!(kept.get("HOL_GUARD_DESKTOP_HOOK_PROXY"), Some(&absolute));
        for refused in [
            source("relative/proxy", "1"),
            source("", "1"),
            source("/p\0q", "1"),
            source(&absolute, "0"),
        ] {
            assert!(isolated_hook_environment(&refused).is_empty());
        }
    }
}
