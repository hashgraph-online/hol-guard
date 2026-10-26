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

/// `cd dashboard` is admitted into the sandbox as the literal directory below
/// the workspace, with no proof from the caller's environment that `CDPATH`
/// is unset. That reading holds because the launcher never hands the run a
/// `CDPATH` to search: the environment is an allow-list, and no entry on it
/// moves where a shell resolves a relative operand. Pin that here, so a name
/// added to the allow-list later cannot quietly give the run a search path
/// the containment shape already assumed away.
#[test]
fn a_contained_run_is_never_given_a_directory_search_path() {
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
    // Every spelling a caller could export: the POSIX name, the name a shell
    // reads case-insensitively on some hosts, and the startup files whose
    // code would run before the first `cd`.
    let source: BTreeMap<String, String> = ["CDPATH", "cdpath", "ENV", "BASH_ENV", "ZDOTDIR"]
        .into_iter()
        .map(|name| (name.to_owned(), "/".to_owned()))
        .collect();
    let environment = filter(
        &source,
        &workspace,
        &workspace,
        &private,
        &private,
        &[],
        false,
    )
    .unwrap();
    for name in source.keys() {
        assert!(
            !environment.contains_key(name),
            "{name} reached the contained run: {environment:?}"
        );
    }
    // The same property stated as the rule rather than the sample, so a new
    // forwarded setting has to answer for it too.
    for name in environment.keys() {
        assert!(
            !name.eq_ignore_ascii_case("CDPATH"),
            "{name} gives the run a directory search path"
        );
    }
    fs::remove_dir_all(&root).unwrap();
}
