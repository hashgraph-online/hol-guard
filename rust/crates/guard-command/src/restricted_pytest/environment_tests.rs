//! The environment a workspace run is given.
use super::*;

/// A workspace run always gets the private `CARGO_HOME` and the offline flag,
/// whether or not the host has fetched a crate yet, and the rustup home when
/// the host has one. An empty registry is an empty cache, not a reason to let
/// a run resolve its toolchain through a home the sandbox denies.
#[test]
fn a_workspace_run_carries_cargos_settings_without_a_host_cache() {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("guard-env-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let workspace = root.join("workspace");
    let private = root.join("private");
    for directory in [&workspace, &private] {
        fs::create_dir(directory).unwrap();
    }
    let environment = filter(
        &BTreeMap::new(),
        &workspace,
        &workspace,
        &private,
        &private,
        &[],
        false,
    )
    .unwrap();
    assert_eq!(
        environment.get("CARGO_HOME").map(String::as_str),
        Some(cargo_home(&private).to_string_lossy().as_ref())
    );
    assert_eq!(
        environment.get("CARGO_NET_OFFLINE").map(String::as_str),
        Some("true")
    );
    let rustup = super::super::toolchains::host_rustup_home()
        .map(|rustup| rustup.to_string_lossy().into_owned());
    assert_eq!(environment.get("RUSTUP_HOME"), rustup.as_ref());

    // A run that names its own executables is not a workspace run, so none of
    // these reaches it.
    let admitted = filter(
        &BTreeMap::new(),
        &workspace,
        &workspace,
        &private,
        &private,
        &[workspace.join("bin/tool")],
        false,
    )
    .unwrap();
    for key in ["CARGO_HOME", "CARGO_NET_OFFLINE", "RUSTUP_HOME"] {
        assert!(!admitted.contains_key(key), "{key}");
    }
    fs::remove_dir_all(&root).unwrap();
}
