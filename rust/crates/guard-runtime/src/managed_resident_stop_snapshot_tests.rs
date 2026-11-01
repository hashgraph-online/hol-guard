use super::*;
use crate::resident_state::{discover_states, publish_state, runtime_digest, state_scope};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TEST_NAME: &str =
    "managed_resident::stop_snapshot::tests::stop_leaves_a_later_signed_generation_alive";

struct Fixture {
    root: std::path::PathBuf,
    children: Vec<Child>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn child(root: &Path, generation: u64) {
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&root.join("native-runtime"), &digest).unwrap();
    let owner: u32 = std::env::var("HOL_GUARD_STOP_SNAPSHOT_OWNER")
        .unwrap()
        .parse()
        .unwrap();
    publish_state(
        &scope,
        generation,
        owner,
        &digest,
        "loopback",
        "127.0.0.1:1".into(),
        &[0x55; crate::AUTH_TOKEN_BYTES],
    )
    .unwrap();
    fs::write(root.join(format!("ready-{generation}")), []).unwrap();
    std::thread::sleep(Duration::from_secs(120));
}

fn spawn(fixture: &mut Fixture, generation: u64) -> usize {
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env("HOL_GUARD_STOP_SNAPSHOT_ROOT", &fixture.root)
        .env("HOL_GUARD_STOP_SNAPSHOT_GENERATION", generation.to_string())
        .env(
            "HOL_GUARD_STOP_SNAPSHOT_OWNER",
            std::process::id().to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    fixture.children.push(child);
    let index = fixture.children.len() - 1;
    let deadline = Instant::now() + Duration::from_secs(20);
    while !fixture.root.join(format!("ready-{generation}")).is_file() {
        assert!(fixture.children[index].try_wait().unwrap().is_none());
        assert!(
            Instant::now() < deadline,
            "private generation did not publish"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    index
}

#[test]
fn stop_leaves_a_later_signed_generation_alive() {
    if let Some(root) = std::env::var_os("HOL_GUARD_STOP_SNAPSHOT_ROOT") {
        child(
            Path::new(&root),
            std::env::var("HOL_GUARD_STOP_SNAPSHOT_GENERATION")
                .unwrap()
                .parse()
                .unwrap(),
        );
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "hol-guard-stop-snapshot-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut fixture = Fixture {
        root,
        children: vec![],
    };
    let digest = runtime_digest().unwrap();
    let scope = state_scope(&fixture.root.join("native-runtime"), &digest).unwrap();
    let original = spawn(&mut fixture, 1);
    let selected = discover_states(&scope, &digest).unwrap().remove(0);
    let stopped = capture(&scope, &digest, &selected).unwrap();
    assert_eq!(stopped.len(), 1);
    fixture.children[original].kill().unwrap();
    fixture.children[original].wait().unwrap();
    let old = &stopped[0];
    super::super::resident_state_retirement::retire_state(
        &scope,
        old.generation,
        old.process_id,
        &old.process_start_marker,
        &digest,
        &[0x55; crate::AUTH_TOKEN_BYTES],
    );
    let later = spawn(&mut fixture, 2);
    let outcome = wait(
        &scope,
        &digest,
        Instant::now() + Duration::from_millis(50),
        &stopped,
    );
    assert_eq!(
        outcome,
        Ok(()),
        "the acknowledged generation already exited"
    );
    assert!(
        fixture.children[later].try_wait().unwrap().is_none(),
        "an earlier Stop must not terminate a later signed generation"
    );
    assert_eq!(discover_states(&scope, &digest).unwrap().len(), 1);

    // The same later process must still be contained when a subsequent Stop
    // explicitly captures it. Its parent reaps it here, after the bounded
    // helper has sent termination; a zombie can keep that helper unverified.
    let selected = discover_states(&scope, &digest).unwrap().remove(0);
    let stopped = capture(&scope, &digest, &selected).unwrap();
    let _ = wait(
        &scope,
        &digest,
        Instant::now() + Duration::from_millis(50),
        &stopped,
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.children[later].try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "captured process was not contained"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
