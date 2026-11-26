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
    debugging_ports: &'static [u16],
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
        debugging_ports: &[],
        quiet: true,
    },
    Vector {
        name: "navigation to localhost in a dedicated profile",
        categories: &["browser_navigation"],
        target: Some("http://localhost:3000/settings"),
        profile: BrowserProfileModeV1::Dedicated,
        debugging_ports: &[],
        quiet: true,
    },
    Vector {
        name: "snapshot of an IPv6 loopback page",
        categories: &["browser_inspection"],
        target: Some("http://[::1]:5180/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: true,
    },
    Vector {
        name: "admin port that frameworks also bind",
        categories: CLICK,
        target: Some("http://127.0.0.1:8001/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "Chrome inspector port",
        categories: CLICK,
        target: Some("http://127.0.0.1:9222/json"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "port the launch records for remote debugging",
        categories: CLICK,
        target: Some("http://127.0.0.1:3001/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[3001],
        quiet: false,
    },
    Vector {
        name: "sensitive surface on a local page",
        categories: &["browser_interaction", "browser_sensitive_surface"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "shared profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::Shared,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "remote-debugging profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::RemoteDebugging,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "unknown profile",
        categories: CLICK,
        target: LOCAL,
        profile: BrowserProfileModeV1::Unknown,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "public origin",
        categories: CLICK,
        target: Some("https://docs.example.test/guide"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "page Guard does not know",
        categories: CLICK,
        target: None,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "loopback port no dev server binds by default",
        categories: CLICK,
        target: Some("http://127.0.0.1:6379/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "file upload",
        categories: &["browser_transfer"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "script evaluation",
        categories: &["browser_privileged"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "routine category beside a non-browser risk",
        categories: &["browser_interaction", "secret_access"],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "websocket scheme",
        categories: &["browser_navigation"],
        target: Some("ws://127.0.0.1:4173/"),
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
        quiet: false,
    },
    Vector {
        name: "no categories",
        categories: &[],
        target: LOCAL,
        profile: BrowserProfileModeV1::Isolated,
        debugging_ports: &[],
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
            debugging_ports: vector.debugging_ports,
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
        debugging_ports: &[],
    };
    with_guard_home(&home.0, || {
        assert!(!loopback_dev_quiet(&facts(
            "http://127.0.0.1:5173/approvals"
        )));
        assert!(loopback_dev_quiet(&facts("http://127.0.0.1:5174/")));
    });
}

#[test]
fn debugging_ports_read_every_flag_spelling() {
    let ports = debugging_ports(
        [
            "--isolated",
            "--remote-debugging-port=9333",
            "--cdp-endpoint",
            "http://127.0.0.1:3002",
            "--browserUrl=http://localhost:4000/",
            "--ws-endpoint",
            "ws://127.0.0.1:8080/devtools/browser/abc",
            "--port=3005",
        ]
        .into_iter(),
    );
    assert_eq!(ports, vec![3002, 4000, 8080, 9333]);
    assert!(debugging_ports(["--isolated", "--port", "3000"].into_iter()).is_empty());
}
