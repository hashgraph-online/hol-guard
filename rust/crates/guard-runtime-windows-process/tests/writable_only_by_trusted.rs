#![cfg(windows)]

use std::path::PathBuf;

use guard_runtime_windows_process::{create_private_directory, writable_only_by_trusted};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::{LocalBox, SecurityDescriptor};

fn directory(name: &str, dacl: &str) -> PathBuf {
    let user = current_process_sid().unwrap().to_string();
    let path = std::env::temp_dir().join(format!("guard-writable-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir(&path);
    let descriptor = format!("O:{user}D:P(A;OICI;FA;;;{user}){dacl}")
        .parse::<LocalBox<SecurityDescriptor>>()
        .unwrap();
    assert!(create_private_directory(&path, &descriptor).unwrap());
    path
}

#[test]
fn only_the_user_system_and_administrators_may_change_the_object() {
    let trusted = directory("trusted", "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let readable = directory("readable", "(A;OICI;FR;;;BU)");
    let child_only = directory("child-only", "(A;OICIIO;FA;;;BU)");
    let writable = directory("writable", "(A;OICI;0x2;;;BU)");
    let deletable = directory("deletable", "(A;;SD;;;AU)");
    let denied = directory("denied", "(D;;FA;;;BU)");
    assert!(writable_only_by_trusted(&trusted));
    assert!(writable_only_by_trusted(&readable));
    assert!(writable_only_by_trusted(&child_only));
    assert!(writable_only_by_trusted(&denied));
    assert!(!writable_only_by_trusted(&writable));
    assert!(!writable_only_by_trusted(&deletable));
    assert!(!writable_only_by_trusted(&trusted.join("missing")));
    for path in [trusted, readable, child_only, writable, deletable, denied] {
        std::fs::remove_dir(path).unwrap();
    }
}
