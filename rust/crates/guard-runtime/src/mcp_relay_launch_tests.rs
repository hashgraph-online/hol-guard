use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::*;
use crate::mcp_relay_args::parse;

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

/// A private scratch directory removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "guard-mcp-relay-{}-{}",
                std::process::id(),
                SCRATCH.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn script(&self, body: &str) -> PathBuf {
        let path = self.0.join("server.sh");
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn relay_args(command: &str, extra: &[&str]) -> RelayArgs {
    let mut argv: Vec<String> = [
        "python",
        "guard",
        "codex-mcp-proxy",
        "--guard-home=/guard/home",
        "--server-name=files",
        "--config-path=/project/config.toml",
    ]
    .iter()
    .map(|token| (*token).to_owned())
    .collect();
    argv.push(format!("--command={command}"));
    argv.extend(extra.iter().map(|token| (*token).to_owned()));
    parse(&argv).unwrap()
}

fn inherited(home: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HOME".to_owned(), home.to_string_lossy().into_owned()),
        ("API_TOKEN".to_owned(), "granted".to_owned()),
        ("AWS_SECRET_ACCESS_KEY".to_owned(), "ambient".to_owned()),
    ])
}

#[test]
fn exit_code_follows_the_python_return_code() {
    assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
    assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
    assert_eq!(exit_code(ExitStatus::from_raw(9)), 247);
    assert_eq!(exit_code(ExitStatus::from_raw(15)), 241);
}

#[test]
fn prepare_scrubs_the_environment_and_pins_the_verified_executable() {
    let scratch = Scratch::new();
    let script = scratch.script("#!/bin/sh\nexit 0\n");
    let args = relay_args(
        &script.to_string_lossy(),
        &["--arg=--root", "--arg=/data", "--server-env-key=API_TOKEN"],
    );
    let launch = prepare(&args, &inherited(&scratch.0), &scratch.0).unwrap();
    assert_eq!(launch.argv[0], script.to_string_lossy());
    assert_eq!(&launch.argv[1..], ["--root", "/data"]);
    assert_eq!(launch.cwd, scratch.0);
    assert_eq!(
        launch.launch_env.get("API_TOKEN").map(String::as_str),
        Some("granted")
    );
    assert!(!launch.launch_env.contains_key("AWS_SECRET_ACCESS_KEY"));
    assert!(!launch.launch_env.contains_key(ORIGIN_HARNESS_ENV));
    assert_eq!(
        launch.child_env.get(ORIGIN_HARNESS_ENV).map(String::as_str),
        Some("codex")
    );
    assert_eq!(
        resolved_runtime_launch_executable(&launch.identity).as_deref(),
        Some(launch.argv[0].as_str())
    );
    assert!(identity_still_matches(&args, &launch));
}

#[test]
fn prepare_refuses_an_unverifiable_executable() {
    let scratch = Scratch::new();
    let args = relay_args("guard-mcp-relay-missing-server", &[]);
    assert_eq!(
        prepare(&args, &inherited(&scratch.0), &scratch.0).unwrap_err(),
        UNVERIFIED
    );
}

#[test]
fn spawn_relays_frames_and_shutdown_returns_the_server_status() {
    let scratch = Scratch::new();
    let script = scratch.script(concat!(
        "#!/bin/sh\n",
        "read line\n",
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}'\n",
        "cat >/dev/null\n",
        "exit 3\n",
    ));
    let args = relay_args(&script.to_string_lossy(), &[]);
    let launch = prepare(&args, &inherited(&scratch.0), &scratch.0).unwrap();
    let mut child = spawn(&args, &launch).unwrap();
    child
        .send(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .unwrap();
    assert_eq!(
        child.next(Duration::from_secs(10)),
        Ok(Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})))
    );
    assert_eq!(child.shutdown(), 3);
}

#[test]
fn spawn_refuses_an_executable_that_changed_after_verification() {
    let scratch = Scratch::new();
    let script = scratch.script("#!/bin/sh\ncat >/dev/null\n");
    let args = relay_args(&script.to_string_lossy(), &[]);
    let launch = prepare(&args, &inherited(&scratch.0), &scratch.0).unwrap();
    fs::write(&script, "#!/bin/sh\necho changed\ncat >/dev/null\n").unwrap();
    assert_eq!(
        spawn(&args, &launch).err(),
        Some(IDENTITY_CHANGED.to_owned())
    );
}
