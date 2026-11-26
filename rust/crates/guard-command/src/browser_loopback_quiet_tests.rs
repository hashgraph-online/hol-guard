use super::*;
use crate::browser_guard_origin::tests::{guard_home, with_guard_home};

fn names(categories: &[&str]) -> Vec<String> {
    categories.iter().map(|name| (*name).to_owned()).collect()
}

struct Vector {
    name: &'static str,
    categories: &'static [&'static str],
    target: Option<&'static str>,
    profile: BrowserProfileModeV1,
    debugging_or_shared_launch: bool,
    quiet: bool,
}

const CLICK: &[&str] = &["browser_interaction"];
const LOCAL: Option<&str> = Some("http://127.0.0.1:4173/");

const VECTORS: &[Vector] = &[
    Vector {
        name: "click on a local dev page in an isolated profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: true,
    },
    Vector {
        name: "navigation to localhost in a dedicated profile",
        categories: &["browser_navigation"],
        target: Some("http://localhost:3000/settings"),
        profile: BrowserProfileModeV1::Dedicated,
        debugging_or_shared_launch: false,
        quiet: true,
    },
    Vector {
        name: "snapshot of an IPv6 loopback page",
        categories: &["browser_inspection"],
        target: Some("http://[::1]:5180/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: true,
    },
    Vector {
        name: "admin port that frameworks also bind",
        categories: CLICK,
        target: Some("http://127.0.0.1:8001/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "Chrome inspector port",
        categories: CLICK,
        target: Some("http://127.0.0.1:9222/json"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "isolated launch beside a remote-debugging or shared flag",
        categories: CLICK,
        target: Some("http://127.0.0.1:3001/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: true,
        quiet: false,
    },
    Vector {
        name: "sensitive surface on a local page",
        categories: &["browser_interaction", "browser_sensitive_surface"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "shared profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::Shared,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "remote-debugging profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::RemoteDebugging,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "unknown profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::Unknown,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "public origin",
        categories: CLICK,
        target: Some("https://docs.example.test/guide"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "page Guard does not know",
        categories: CLICK,
        target: None,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "loopback port no dev server binds by default",
        categories: CLICK,
        target: Some("http://127.0.0.1:6379/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "file upload",
        categories: &["browser_transfer"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "script evaluation",
        categories: &["browser_privileged"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "routine category beside a non-browser risk",
        categories: &["browser_interaction", "secret_access"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "websocket scheme",
        categories: &["browser_navigation"],
        target: Some("ws://127.0.0.1:4173/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "user name and password in a loopback URL",
        categories: &["browser_navigation"],
        target: Some("http://dev:pw@127.0.0.1:4173/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "user name alone in a loopback URL",
        categories: &["browser_navigation"],
        target: Some("http://dev@localhost:3000/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "opaque-token query on a loopback URL",
        categories: &["browser_navigation"],
        target: Some(
            "http://127.0.0.1:4173/callback?state=Q7rVm2XkP9wLs4TnB8yHc3JdF6gZa1Ne5uRt0WqYb",
        ),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
    Vector {
        name: "readable query on a loopback URL",
        categories: &["browser_navigation"],
        target: Some("http://127.0.0.1:4173/search?q=release-notes&page=2"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: true,
    },
    Vector {
        name: "no categories",
        categories: &[],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
        quiet: false,
    },
];

#[test]
fn quiet_set_vectors() {
    // A home whose daemon records a port no vector uses, so only the R-SELF vector below reaches
    // Guard's origin.
    let home = guard_home("quiet-vectors", Some(51234));
    for vector in VECTORS {
        let categories = names(vector.categories);
        let facts = LoopbackQuietFacts {
            categories: &categories,
            target: vector.target,
            profile: vector.profile,
            debugging_or_shared_launch: vector.debugging_or_shared_launch,
        };
        assert_eq!(
            with_guard_home(&home.0, || loopback_dev_quiet(&facts)),
            vector.quiet,
            "{}",
            vector.name
        );
    }
}

#[test]
fn guard_origin_is_never_quiet() {
    // The daemon may record a port development servers also bind by default.
    let home = guard_home("quiet-self", Some(5173));
    let categories = names(CLICK);
    let facts = |target| LoopbackQuietFacts {
        categories: &categories,
        target: Some(target),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
    };
    with_guard_home(&home.0, || {
        assert!(!loopback_dev_quiet(&facts(
            "http://127.0.0.1:5173/approvals"
        )));
        assert!(loopback_dev_quiet(&facts("http://127.0.0.1:5174/")));
    });
}

#[test]
fn the_daemon_fallback_range_is_never_quiet_while_no_state_records_a_port() {
    let categories = names(CLICK);
    let facts = |target| LoopbackQuietFacts {
        categories: &categories,
        target: Some(target),
        profile: BrowserProfileModeV1::Isolated,
        debugging_or_shared_launch: false,
    };
    let unrecorded = guard_home("quiet-no-state", None);
    with_guard_home(&unrecorded.0, || {
        assert!(!loopback_dev_quiet(&facts("http://127.0.0.1:5173/")));
        assert!(!loopback_dev_quiet(&facts("http://127.0.0.1:5000/")));
        assert!(loopback_dev_quiet(&facts("http://127.0.0.1:3000/")));
        assert!(loopback_dev_quiet(&facts("http://127.0.0.1:4173/")));
    });
    let recorded = guard_home("quiet-recorded", Some(51236));
    with_guard_home(&recorded.0, || {
        assert!(loopback_dev_quiet(&facts("http://127.0.0.1:5173/")));
    });
}
