#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use guard_runtime_windows_process::{ChildTree, CHILD_TREE_CREATION_FLAGS};

fn long_running(flags: u32) -> Child {
    Command::new("cmd.exe")
        .args(["/d", "/c", "ping -n 60 127.0.0.1 >nul"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(flags)
        .spawn()
        .unwrap()
}

fn exited_within(child: &mut Child, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn adopted_child_runs_until_the_tree_is_terminated() {
    let mut child = long_running(CHILD_TREE_CREATION_FLAGS);
    let tree = ChildTree::adopt_suspended(&child).unwrap();
    assert!(!exited_within(&mut child, Duration::from_millis(500)));
    tree.terminate().unwrap();
    assert!(exited_within(&mut child, Duration::from_secs(10)));
    tree.terminate().unwrap();
}

#[test]
fn dropping_the_tree_kills_the_child() {
    let mut child = long_running(CHILD_TREE_CREATION_FLAGS);
    drop(ChildTree::adopt_suspended(&child).unwrap());
    assert!(exited_within(&mut child, Duration::from_secs(10)));
}

#[test]
fn a_running_child_is_not_adopted() {
    let mut child = long_running(0);
    let adopted = ChildTree::adopt_suspended(&child);
    let _ = child.kill();
    let _ = child.wait();
    assert!(adopted.is_err());
}
