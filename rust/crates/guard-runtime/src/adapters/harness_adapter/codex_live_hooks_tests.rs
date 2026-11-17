use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::super::codex_python_hook::inline_codex_hook;
use super::*;

fn posix() -> Syntax {
    Syntax::new(false, BTreeMap::new())
}

fn refused(command: &str) -> bool {
    conflict(command, "unmanaged", (None, None), &mut posix()).is_some()
}

fn hook_args() -> Vec<String> {
    ["hook", "--harness", "codex"].map(str::to_owned).to_vec()
}

const CLI: &str = "codex_plugin_scanner.cli";

#[test]
fn module_hooks_need_the_exact_codex_harness() {
    for options in [
        "",
        "-W ignore",
        "-X dev",
        "--check-hash-based-pycs always",
        "-I -W ignore -X dev",
        "-Wignore",
        "-Xdev",
        "-IW ignore",
    ] {
        for argument in ["--harness codex", "--harness=codex"] {
            assert!(
                refused(&format!("python {options} -m {CLI} guard hook {argument}")),
                "{options} {argument}"
            );
        }
    }
    for argument in [
        "--harness codex-other",
        "--harness=codexevil",
        "--harness claude",
    ] {
        assert!(!refused(&format!(
            "python -W ignore -X dev -m {CLI} guard hook {argument}"
        )));
    }
    for launcher in ["-mcodex_plugin_scanner.cli", "-Im codex_plugin_scanner.cli"] {
        assert!(refused(&format!("python {launcher} hook --harness codex")));
    }
    assert!(!refused(&format!(
        "python -- -m {CLI} guard hook --harness codex"
    )));
}

#[test]
fn bridge_script_is_judged_where_python_runs_it() {
    for options in [
        "-W ignore",
        "-X dev",
        "--check-hash-based-pycs always",
        "--",
    ] {
        assert!(refused(&format!(
            "python {options} /opt/guard/codex_daemon_hook_bridge.py"
        )));
    }
    assert!(!refused(
        "python third-party.py /opt/guard/codex_daemon_hook_bridge.py"
    ));
}

#[test]
fn inline_scripts_that_load_the_cli_with_codex_arguments_conflict() {
    let codex = [
        "from codex_plugin_scanner.cli import main; main(['guard','hook','--harness','codex'])",
        "from codex_plugin_scanner.cli import main; main(['guard','hook','--harness',harness_var])",
        "from codex_plugin_scanner.cli import main; extra = '--json'; main(['guard','hook','--harness','codex',extra])",
    ];
    for script in codex {
        assert!(inline_codex_hook(script, &[]), "{script}");
    }
    assert!(!inline_codex_hook(
        "from codex_plugin_scanner.cli import main; main(['guard','hook','--harness','claude'])",
        &[]
    ));
    for script in [
        "# from codex_plugin_scanner.cli import main\nprint(['guard','hook','--harness','codex'])",
        "module = 'codex_plugin_scanner.cli'; print(['guard','hook','--harness','codex'])",
        "print 'python two'",
        "def broken(:",
    ] {
        assert!(!inline_codex_hook(script, &[]), "{script}");
    }
    assert!(inline_codex_hook(
        "from codex_plugin_scanner import cli; cli.main()",
        &hook_args()
    ));
}

#[test]
fn dynamic_imports_of_the_cli_conflict_through_local_bindings() {
    let scripts = [
        "import runpy,sys; sys.argv[1:]=['hook','--harness','codex']; runpy.run_module('codex_plugin_scanner.cli',run_name='__main__')",
        "import importlib; importlib.import_module('codex_plugin_scanner.cli').main(['hook','--harness','codex'])",
        "__import__('codex_plugin_scanner.cli',fromlist=['main']).main(['hook','--harness','codex'])",
        "import runpy; runpy.run_module(*(), mod_name='codex_plugin_scanner.cli')",
        "__import__(*(), name='codex_plugin_scanner.cli',fromlist=['main'])",
        "import runpy\ndef unrelated(): runpy = None\nrunpy.run_module(mod_name='codex_plugin_scanner.cli',run_name='__main__')",
        "def unrelated(): __import__ = None\n__import__(name='codex_plugin_scanner.cli')",
        "try: pass\nexcept Exception as __import__: pass\n__import__(name='codex_plugin_scanner.cli')",
        "import runpy\nunused = [runpy for runpy in []]\nrunpy.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy\nunused = lambda: (runpy := None)\nrunpy.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy\nfor runpy in []: pass\nrunpy.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy\nif flag: runpy = None\nrunpy.run_module(mod_name='codex_plugin_scanner.cli')",
        "__import__: object\n__import__(name='codex_plugin_scanner.cli')",
        "__import__ = None\ndel __import__\n__import__(name='codex_plugin_scanner.cli')",
        "__import__('importlib').import_module(name='codex_plugin_scanner.cli')",
        "from builtins import __import__ as load\nload('runpy').run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy\nclass Unrelated:\n runpy = None\n def invoke(self): runpy.run_module(mod_name='codex_plugin_scanner.cli')\nUnrelated().invoke()",
        "def run(): runpy.run_module('codex_plugin_scanner.cli',run_name='__main__')\nimport runpy\nrun()",
        "def load():\n global runpy\n import runpy\nload()\nrunpy.run_module(mod_name='codex_plugin_scanner.cli')",
        "run = lambda: runpy.run_module(mod_name='codex_plugin_scanner.cli')\nimport runpy\nrun()",
        "import runpy\ndef load():\n global launch\n launch = runpy.run_module\nload()\nlaunch(mod_name='codex_plugin_scanner.cli')",
        "def run(): runpy.run_module('codex_plugin_scanner.cli')\ndef load():\n global runpy\n import runpy\nload()\nrun()",
        "import runpy; left,right=runpy,runpy; left.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; runpy,launch=None,runpy; launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; (unused,(launch,))=(None,(runpy,)); launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; [launch]=[runpy]; launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; launch,*rest=(runpy,None); launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; *rest,launch=(None,runpy); launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; launch,=(*[runpy],); launch.run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; first,*rest=(None,runpy); rest[0].run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; modules=[runpy]; modules[-1].run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy\nif flag: modules=[runpy]\nelse: modules=[None,None]\nmodules[-1].run_module(mod_name='codex_plugin_scanner.cli')",
        "import runpy; [launch := runpy for _ in [0]]; launch.run_module('codex_plugin_scanner.cli')",
        "import runpy\ndef run():\n [launch := runpy for _ in [0]]\n launch.run_module('codex_plugin_scanner.cli')\nrun()",
        "import runpy; [[launch := runpy for _ in [0]] for _ in [0]]; launch.run_module('codex_plugin_scanner.cli')",
    ];
    for script in scripts {
        assert!(inline_codex_hook(script, &hook_args()), "{script}");
    }
    let deep = format!(
        "{}1\nimport runpy\nrunpy.run_module('codex_plugin_scanner.cli')",
        "1+".repeat(600)
    );
    assert!(inline_codex_hook(&deep, &hook_args()));
}

#[test]
fn same_named_helpers_are_not_the_import_apis() {
    let scripts = [
        "def import_module(**kwargs): return None\nimport_module(name='codex_plugin_scanner.cli')",
        "def run_module(**kwargs): return None\nrun_module(mod_name='codex_plugin_scanner.cli')",
        "def __import__(**kwargs): return None\n__import__(name='codex_plugin_scanner.cli')",
        "try: pass\nexcept Exception as __import__: __import__(name='codex_plugin_scanner.cli')",
        "from third_party import __import__; __import__(name='codex_plugin_scanner.cli')",
        "import runpy; first,*rest=(None,runpy); rest.run_module(mod_name='codex_plugin_scanner.cli')",
    ];
    for script in scripts {
        assert!(!inline_codex_hook(script, &hook_args()), "{script}");
    }
}

#[test]
fn live_handlers_and_their_missing_programs() {
    let mut syntax = posix();
    assert!(live("/opt/rt codex-hook-bridge {}", &mut syntax));
    assert!(!live("/opt/rt codex-hook-bridge", &mut syntax));
    assert!(live("/opt/hol-guard hook --harness codex", &mut syntax));
    assert!(!live("/opt/hol-guard hook --harness claude", &mut syntax));
    assert!(live(
        "python -c 'import codex_plugin_scanner.cli; guard hook'",
        &mut syntax
    ));
    let gone =
        "/nonexistent-guard-test/bin/python /nonexistent-guard-test/codex_daemon_hook_bridge.py";
    let expected = (!cfg!(windows)).then(|| "/nonexistent-guard-test/bin/python".to_owned());
    assert_eq!(missing_program(gone, &mut syntax), expected);
    assert_eq!(
        missing_program(
            "python -m codex_plugin_scanner.cli guard hook --harness codex",
            &mut syntax
        ),
        None
    );
}

#[test]
fn owner_message_names_place_and_remedy() {
    let message = owner_message(
        "cmd",
        None,
        (
            Some("PreToolUse/group[0]/handler[0]"),
            Some("/x/hooks.json"),
        ),
    );
    assert!(message.starts_with("codex_hook_owner_conflict: An existing Codex Guard handler at PreToolUse/group[0]/handler[0] in /x/hooks.json"));
    assert!(message.ends_with("Delete that handler from /x/hooks.json, then run `hol-guard install codex`; existing hooks have been preserved."));
    let dead = owner_message("cmd", Some("/gone".to_owned()), (None, None));
    assert!(dead.contains("handler runs /gone, which no longer exists"));
    assert!(dead.contains("from your Codex hooks configuration"));
}

fn hooks_text(command: &str, matcher: &str) -> String {
    let group =
        json!([{ "matcher": matcher, "hooks": [{ "type": "command", "command": command }] }]);
    json!({ "PreToolUse": group, "PermissionRequest": group }).to_string()
}

fn ask(op: &str, extra: Value) -> Value {
    let mut fields: Map<String, Value> = extra.as_object().cloned().unwrap_or_default();
    fields.insert("op".to_owned(), json!(op));
    fields.insert("windows".to_owned(), json!(false));
    fields.insert("long_paths".to_owned(), json!({}));
    super::super::codex_owners::dispatch(&fields).unwrap_or_else(|_| json!("refused"))
}

#[test]
fn matches_and_intercept_through_dispatch() {
    let answer = ask(
        "matches",
        json!({ "hooks": hooks_text("/opt/rt codex-hook-bridge {}", "Bash") }),
    );
    assert_eq!(answer["matches"]["PreToolUse"], json!(true));
    assert_eq!(answer["matches"]["PostToolUse"], json!(false));
    let interceptable = !cfg!(windows) || answer["intercept"] == json!(true);
    assert!(interceptable);
    let other = ask(
        "matches",
        json!({ "hooks": hooks_text("/opt/rt codex-hook-bridge {}", "Read") }),
    );
    assert_eq!(other["intercept"], json!(false));
    assert_eq!(
        ask("matches", json!({ "hooks": "{}", "extra": 1 })),
        json!("refused")
    );
}

#[test]
fn a_hooks_value_that_is_not_a_table_routes_nothing() {
    for hooks in ["[]", "null", "\"PreToolUse\"", "3"] {
        let answer = ask("matches", json!({ "hooks": hooks }));
        let events = answer["matches"].as_object().unwrap();
        assert_eq!(events.len(), EVENTS.len(), "{hooks}");
        assert!(
            events.values().all(|found| found == &json!(false)),
            "{hooks}"
        );
        assert_eq!(answer["intercept"], json!(false), "{hooks}");
    }
    assert_eq!(ask("matches", json!({ "hooks": "{" })), json!("refused"));
}

#[test]
fn install_refuses_an_unowned_guard_handler_and_appends_otherwise() {
    let fields = |hooks: String| {
        json!({
            "hooks": hooks,
            "managed": json!({ "PreToolUse": { "hooks": [] } }).to_string(),
            "cwd": null,
            "guard_home": "/guard-home",
            "package_root": "/package",
        })
    };
    let refused = ask(
        "install",
        fields(hooks_text(
            &format!("python -m {CLI} guard hook --harness codex"),
            "Bash",
        )),
    );
    let message = refused["conflict"].as_str().unwrap_or_default();
    assert!(
        message.contains("at PreToolUse/group[0]/handler[0]"),
        "{refused}"
    );
    let added = ask("install", fields(hooks_text("/usr/bin/other-tool", "Bash")));
    let hooks: Value =
        serde_json::from_str(added["hooks"].as_str().unwrap_or("null")).unwrap_or_default();
    assert_eq!(hooks["PreToolUse"].as_array().map(Vec::len), Some(2));
}

#[test]
fn overlay_keeps_stale_cli_ownership_only() {
    let hooks = hooks_text("/opt/rt codex-hook-bridge {}", "Bash");
    let stale = json!({ "integrity_status": "invalid", "integrity_reason": "codex_hook_manifest_package_version_stale" });
    let kept = ask("overlay", json!({ "hooks": hooks, "integrity": stale }));
    assert_eq!(kept["matches"]["PreToolUse"], json!(true));
    let tampered = json!({ "integrity_status": "invalid", "integrity_reason": "codex_hook_registration_mismatch" });
    let dropped = ask("overlay", json!({ "hooks": hooks, "integrity": tampered }));
    assert_eq!(dropped["matches"]["PreToolUse"], json!(false));
}

#[test]
fn doctor_copy_and_status() {
    let state = json!({ "config_present": true, "codex_hooks_enabled": true, "managed_hook_installed": true, "integrity_status": "valid", "protection_active": true });
    let answer = ask(
        "doctor",
        json!({ "warnings": ["Guard is not installed for this harness."], "hook_state": state, "base_status": "partial" }),
    );
    assert_eq!(answer, json!({ "warnings": [], "status": "active" }));
    let missing = json!({ "config_present": true, "codex_hooks_enabled": false });
    let answer = ask(
        "doctor",
        json!({ "warnings": [], "hook_state": missing, "base_status": "active" }),
    );
    assert_eq!(answer["status"], json!("broken"));
    assert_eq!(answer["warnings"].as_array().map(Vec::len), Some(2));
}

#[test]
fn doctor_reads_the_integrity_status_not_a_flag() {
    let ask_with = |status: Value| {
        let state = json!({ "config_present": true, "codex_hooks_enabled": true, "managed_hook_installed": true, "integrity_status": status, "protection_active": true });
        ask(
            "doctor",
            json!({ "warnings": [], "hook_state": state, "base_status": "partial" }),
        )
    };
    assert_eq!(
        ask_with(json!("valid")),
        json!({ "warnings": [], "status": "active" })
    );
    for status in [json!("stale"), json!("invalid"), json!(true), json!(null)] {
        let answer = ask_with(status.clone());
        let warnings = answer["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("do not match this Guard CLI")),
            "{status}"
        );
    }
}

#[test]
fn doctor_never_calls_untrusted_hooks_active() {
    let state = |stale: bool| json!({ "config_present": true, "codex_hooks_enabled": true, "managed_hook_installed": true, "integrity_status": "valid", "protection_active": true, "hook_trust_stale": stale });
    let ask_with = |stale: bool| {
        ask(
            "doctor",
            json!({ "warnings": ["existing"], "hook_state": state(stale), "base_status": "active" }),
        )
    };
    let stale = ask_with(true);
    assert_eq!(stale["status"], json!("partial"));
    let warnings = stale["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| {
        let w = w.as_str().unwrap();
        w.contains("/hooks") && w.contains("press t")
    }));
    let trusted = ask_with(false);
    assert_eq!(trusted["status"], json!("active"));
    assert_eq!(trusted["warnings"], json!(["existing"]));
    let broken =
        json!({ "config_present": true, "codex_hooks_enabled": false, "hook_trust_stale": true });
    let answer = ask(
        "doctor",
        json!({ "warnings": [], "hook_state": broken, "base_status": "active" }),
    );
    assert_eq!(answer["status"], json!("broken"));
}
