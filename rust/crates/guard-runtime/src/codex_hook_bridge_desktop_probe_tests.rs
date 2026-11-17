use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::*;

fn target(data: &str) -> Target<'_> {
    Target {
        data,
        guard_home: "/g/./home/".to_owned(),
        home: "/Users/u ü".to_owned(),
        workspace: "/work".to_owned(),
        timeout_seconds: 25,
        deadline: Instant::now() + Duration::from_secs(8),
    }
}

fn desktop(proxy: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (DESKTOP_ENV.to_owned(), "1".to_owned()),
        (PROXY_ENV.to_owned(), proxy.to_owned()),
    ])
}

#[test]
fn the_config_is_the_one_the_bounded_hook_command_writes() {
    let config = config("/A.app/Contents/MacOS/proxy", "/core/lib", &target("{}"));
    assert_eq!(
        config,
        concat!(
            r#"{"python_executable":"/A.app/Contents/MacOS/proxy","package_root":"/core/lib","#,
            r#""guard_home":"/g/home","cli_args":["guard","hook","--guard-home","/g/home","#,
            r#""--harness","codex","--home","/Users/u \u00fc","--workspace","/work"],"#,
            r#""harness":"codex","timeout_seconds":25.0,"frozen_launcher":true}"#,
        )
    );
}

#[test]
fn only_an_absolute_proxy_the_desktop_app_named_is_used() {
    assert_eq!(proxy(&desktop("/A.app/p")), Some("/A.app/p"));
    for refused in ["", "relative/p", "/A.app/p\0x"] {
        assert_eq!(proxy(&desktop(refused)), None, "{refused:?}");
    }
    let mut not_desktop = desktop("/A.app/p");
    not_desktop.insert(DESKTOP_ENV.to_owned(), "0".to_owned());
    assert_eq!(proxy(&not_desktop), None);
    assert_eq!(proxy(&BTreeMap::new()), None);
}

#[test]
fn a_proxy_that_does_not_verify_answers_nothing() {
    let missing = std::env::temp_dir().join("no-such.app/Contents/MacOS/proxy");
    let environment = desktop(missing.to_str().unwrap());
    assert_eq!(answer("/core", &target("{}"), &environment), None);
    assert_eq!(answer("/core", &target("{}"), &BTreeMap::new()), None);
}
