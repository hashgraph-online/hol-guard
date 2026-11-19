use serde_json::{json, Value};

use crate::cursor_hook_config::dispatch;
use crate::cursor_hook_rebind::ephemeral_desktop_cli;
use crate::runner_authority_op::ERR_INVALID;

const DOCSTRING: &str =
    "\"\"\"Managed by HOL Guard. Re-run `hol-guard install cursor` after moving Guard home.\"\"\"";

fn script(argv0: &str) -> String {
    format!(
        "#!/usr/bin/env python3\n{DOCSTRING}\nGUARD_CLI = {cli}\nGUARD_RECOVERY_COMMAND = {cli}\n",
        cli = json!([argv0, "hook"]),
    )
}

fn ask(op: &str, fields: Value) -> Value {
    let mut request = json!({"op": op, "windows": false, "long_paths": {}});
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    dispatch(&request).expect("answer")
}

fn rebind(fields: Value) -> bool {
    let mut request = json!({
        "managed": null,
        "commands": [],
        "isolated_python": false,
        "native_bridge": false,
    });
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    ask("rebind", request)["rebind"].as_bool().unwrap()
}

#[test]
fn launchers_desktop_can_prune_are_ephemeral() {
    for path in [
        "/app/core/versions/1.2.3/hol-guard",
        "/app/core/versions/1.2.3/bundle/hol-guard",
        "/app/core/Versions/1.2.3/HOL-GUARD",
        "/app/core/bundled/1.2.3/bin/hol-guard",
        "/app/core/bundled/1.2.3/lib/hol-guard-core/hol-guard",
        "/app/core/versions/./1.2.3//hol-guard",
    ] {
        assert!(ephemeral_desktop_cli(path, false), "{path}");
    }
    for path in [
        "/app/core/current-hol-guard",
        "/app/core/versions/hol-guard",
        "/app/core/versions/1.2.3/bin/x/hol-guard",
        "/app/core/versions/1.2.3/other",
        "/app/core/bundled/1.2.3/Bin/hol-guard",
        "C:\\core\\versions\\1.2.3\\hol-guard.exe",
        "",
    ] {
        assert!(!ephemeral_desktop_cli(path, false), "{path}");
    }
    assert!(ephemeral_desktop_cli(
        "C:\\core\\versions\\1.2.3\\hol-guard.exe",
        true
    ));
}

#[test]
fn only_managed_scripts_bake_an_ephemeral_cli() {
    let versioned = script("/core/versions/1.0/hol-guard");
    assert_eq!(
        ask("ephemeral", json!({"source": versioned}))["ephemeral"],
        true
    );
    let shim = script("/core/current-hol-guard");
    assert_eq!(
        ask("ephemeral", json!({"source": shim}))["ephemeral"],
        false
    );
    let unmanaged = versioned.replace(DOCSTRING, "");
    assert_eq!(
        ask("ephemeral", json!({"source": unmanaged}))["ephemeral"],
        false
    );
    let recovery_only = format!(
        "{DOCSTRING}\nGUARD_CLI = [\"/core/current-hol-guard\"]\nGUARD_RECOVERY_COMMAND = [\"/core/versions/1/hol-guard\"]\n"
    );
    assert_eq!(
        ask("ephemeral", json!({"source": recovery_only}))["ephemeral"],
        true
    );
    let not_a_list = format!(
        "{DOCSTRING}\nGUARD_CLI = \"/core/versions/1/hol-guard\"\nGUARD_RECOVERY_COMMAND = [1]\n"
    );
    assert_eq!(
        ask("ephemeral", json!({"source": not_a_list}))["ephemeral"],
        false
    );
}

#[test]
fn a_current_script_needs_no_rebind() {
    let current = script("/core/current-hol-guard");
    assert!(!rebind(json!({"live": current, "expected": current})));
    assert!(!rebind(
        json!({"live": current, "managed": current, "expected": current})
    ));
}

#[test]
fn a_stale_or_ephemeral_script_needs_a_rebind() {
    let current = script("/core/current-hol-guard");
    let old = script("/core/old-hol-guard");
    let versioned = script("/core/versions/1/hol-guard");
    assert!(rebind(json!({"live": old, "expected": current})));
    assert!(rebind(
        json!({"live": current, "managed": old, "expected": current})
    ));
    assert!(rebind(json!({"live": versioned, "expected": versioned})));
    assert!(rebind(
        json!({"live": current, "managed": versioned, "expected": current})
    ));
}

#[test]
fn frozen_hooks_rebind_only_with_an_isolated_python() {
    let current = script("/core/current-hol-guard");
    let commands = json!([["/rt cursor-hook-bridge /home/.cursor/hooks/x.py", true]]);
    assert!(!rebind(
        json!({"live": current, "expected": current, "commands": commands})
    ));
    assert!(rebind(json!({
        "live": current, "expected": current, "commands": commands, "isolated_python": true,
    })));
}

#[test]
fn hooks_that_skip_the_native_bridge_rebind_when_it_can_answer() {
    let current = script("/core/current-hol-guard");
    let bridged = json!([["/rt cursor-hook-bridge /home/.cursor/hooks/x.py", false]]);
    let direct = json!([["/usr/bin/python3 /home/.cursor/hooks/x.py", false]]);
    for (commands, bridge, expected) in [
        (&bridged, true, false),
        (&direct, false, false),
        (&direct, true, true),
        (&json!([]), true, false),
    ] {
        assert_eq!(
            rebind(json!({
                "live": current, "expected": current, "commands": commands, "native_bridge": bridge,
            })),
            expected,
            "{commands} {bridge}"
        );
    }
}

#[test]
fn malformed_rebind_requests_are_refused() {
    let base = json!({
        "op": "rebind", "windows": false, "long_paths": {},
        "live": "", "managed": null, "expected": "", "commands": [],
        "isolated_python": false, "native_bridge": false,
    });
    assert!(dispatch(&base).is_ok());
    for (key, value) in [
        ("managed", json!(1)),
        ("commands", json!([["x"]])),
        ("isolated_python", json!(null)),
    ] {
        let mut request = base.clone();
        request[key] = value;
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{key}");
    }
    let mut extra = base.clone();
    extra["extra"] = json!(1);
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
}
