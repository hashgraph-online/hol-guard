use super::*;

#[test]
fn bytecode_and_the_pytest_cache_stay_in_the_private_directory() {
    let private = Path::new("/private/tmp/hol guard-workspace-x");
    let mut environment = BTreeMap::new();
    settle(&mut environment, private).expect("settled");
    let cache = "/private/tmp/hol guard-workspace-x/tmp/pytest-cache";
    assert_eq!(environment["PYTHONDONTWRITEBYTECODE"], "1");
    assert_eq!(
        environment["PYTEST_ADDOPTS"],
        format!("-o cache_dir={}", crate::mcp_proxy_shlex::quote(cache))
    );
    assert_eq!(
        environment["PYTEST_ADDOPTS"],
        format!("-o cache_dir='{cache}'")
    );
}

#[test]
fn a_linked_user_site_is_the_root_the_run_may_read() {
    let private = tempfile::tempdir().expect("private");
    std::fs::create_dir(private.path().join("home")).expect("home");
    let link = private.path().join("home/Library/Python");
    match link_user_site(private.path()).expect("linked") {
        Some(root) => assert_eq!(std::fs::read_link(&link).expect("link"), Path::new(&root)),
        None => assert!(!private.path().join("home/Library").exists()),
    }
}
