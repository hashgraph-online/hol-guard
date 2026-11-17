use super::legacy_tail;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn a_native_launcher_prefix_is_dropped_before_the_tail() {
    let wrapped = argv(&["/g/rt", "codex-hook-bridge", "/py", "bridge.py", "--home"]);
    assert_eq!(legacy_tail(&wrapped), ["bridge.py", "--home"]);
}

#[test]
fn the_current_registration_is_its_own_identity() {
    let current = argv(&["/g/rt", "codex-hook-bridge", "/c/config.toml"]);
    assert_eq!(
        legacy_tail(&current),
        ["codex-hook-bridge", "/c/config.toml"]
    );
    let empty_runtime = argv(&["", "codex-hook-bridge", "a", "b"]);
    assert_eq!(legacy_tail(&empty_runtime), ["codex-hook-bridge", "a", "b"]);
    assert!(legacy_tail(&[]).is_empty());
    assert!(legacy_tail(&argv(&["only"])).is_empty());
}
