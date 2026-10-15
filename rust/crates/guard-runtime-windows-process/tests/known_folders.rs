#![cfg(windows)]

use guard_runtime_windows_process::trusted_install_roots;

#[test]
fn trusted_install_roots_ignore_environment_overrides() {
    let decoy = std::env::temp_dir().join("guard-known-folder-decoy");
    let roots = trusted_install_roots();
    // This test binary holds only this test, so changing the environment
    // cannot race another test.
    std::env::set_var("ProgramFiles", &decoy);
    std::env::set_var("ProgramFiles(x86)", &decoy);
    std::env::set_var("SystemRoot", &decoy);
    std::env::remove_var("ProgramW6432");
    assert_eq!(trusted_install_roots(), roots);
    assert!(!roots.contains(&decoy));
    assert!(roots.iter().all(|root| root.is_absolute() && root.is_dir()));
    // The Windows directory holds user-writable descendants such as Temp.
    assert!(!roots
        .iter()
        .any(|root| root.join("System32").join("cmd.exe").exists()));
    assert!(roots.iter().any(|root| root.join("Common Files").is_dir()));
}
