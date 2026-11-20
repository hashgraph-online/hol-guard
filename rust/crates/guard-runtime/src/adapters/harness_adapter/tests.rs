//! The `harness_adapter` kind against throwaway homes: each op as the
//! Python adapter it replaces answered it.

use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tempfile::TempDir;

use super::dispatch;

#[path = "tests_claude.rs"]
mod claude_family;
#[path = "tests_cline.rs"]
mod cline_family;
#[path = "tests_cline_opencode_apply.rs"]
mod cline_opencode_apply_family;
#[path = "tests_codex.rs"]
mod codex_family;
#[path = "tests_contract_config_paths.rs"]
mod contract_config_paths_family;
#[path = "tests_copilot.rs"]
mod copilot_family;
#[path = "tests_cursor.rs"]
mod cursor_family;
#[path = "tests_cursor_surfaces.rs"]
mod cursor_surfaces_family;
#[path = "tests_detect_merged.rs"]
mod detect_merged_family;
#[path = "tests_firewall.rs"]
mod firewall_family;
#[path = "tests_grok_zcode.rs"]
mod grok_zcode;
#[cfg(unix)]
#[path = "guard_home_redirect_tests.rs"]
mod guard_home_redirect_family;
#[path = "tests_hermes.rs"]
mod hermes_family;
#[path = "tests_hook_config.rs"]
mod hook_config_family;
#[path = "tests_install_apply.rs"]
mod install_apply_family;
#[path = "tests_live_hook_verification.rs"]
mod live_hook_verification_family;
#[path = "managed_install_tests.rs"]
mod managed_install_family;
#[path = "tests_mcp_servers.rs"]
mod mcp_servers_family;
#[path = "tests_opencode.rs"]
mod opencode_family;
#[path = "tests_pi.rs"]
mod pi_family;
#[path = "tests_probe_run.rs"]
mod probe_run_family;
#[path = "tests_round_trip.rs"]
mod round_trip;
#[path = "tests_setup_detection.rs"]
mod setup_detection_family;
#[path = "tests_shims.rs"]
mod shim_family;
#[path = "tests_shims_apply.rs"]
mod shims_apply_family;
#[cfg(unix)]
#[path = "standalone_install_tests.rs"]
mod standalone_install_family;
#[path = "update_tests.rs"]
mod update_family;
#[path = "update_store_tests.rs"]
mod update_store_family;

struct Home {
    _dir: TempDir,
    root: std::path::PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        fs::create_dir_all(root.join("guard")).unwrap();
        Self { _dir: dir, root }
    }

    fn home(&self) -> std::path::PathBuf {
        self.root.join("home")
    }

    fn guard(&self) -> std::path::PathBuf {
        self.root.join("guard")
    }

    fn context(&self, mut env: Value) -> Value {
        // Never read the host's real Claude Code managed policy.
        if let Some(env) = env.as_object_mut() {
            env.entry("HOL_GUARD_TEST_CLAUDE_MANAGED_SETTINGS")
                .or_insert_with(|| json!(self.root.join("managed-settings.json")));
        }
        json!({
            "home": self.home(),
            "workspace": null,
            "guard_home": self.guard(),
            "home_override_explicit": false,
            "cwd": self.root,
            "user_home": self.home(),
            "env": env,
            "caller": caller(false),
        })
    }

    fn ask(&self, harness: &str, op: &str, extra: Value) -> Value {
        self.ask_env(harness, op, extra, json!({"PATH": ""}))
    }

    fn ask_env(&self, harness: &str, op: &str, extra: Value, env: Value) -> Value {
        let mut request = json!({"harness": harness, "op": op, "context": self.context(env)});
        for (key, value) in extra.as_object().unwrap() {
            // A test's own `caller` replaces the context's default one.
            if key == "caller" {
                request["context"]["caller"] = value.clone();
            } else {
                request[key] = value.clone();
            }
        }
        dispatch(&request).unwrap()
    }
}

/// `native_caller.caller_identity()` for a source (or `frozen`) Guard.
fn caller(frozen: bool) -> Value {
    json!({
        "executable": "/py",
        "executable_resolved": "/py",
        "frozen": frozen,
        "launcher": if frozen { "/g/bin/hol-guard" } else { "/py" },
        "frozen_launcher": frozen.then_some("/g/bin/hol-guard-core"),
        "cli_executable": "/py",
        "package_root": "/opt/guard/site",
        "version": "0.0.0",
        "native_runtime": {
            "path": "/g/hol-guard-runtime",
            "size": 3,
            "sha256": "0".repeat(64),
            "features": NATIVE_FEATURES,
        },
    })
}

/// What the stamped test runtime advertises: every hook bridge.
const NATIVE_FEATURES: [&str; 8] = [
    "codex-hook-bridge-v1",
    "cursor-hook-bridge-v1",
    "claude-hook-bridge-v1",
    "claude-session-start-v1",
    "cline-hook-worker-v1",
    "pi-hook-bridge-v1",
    "bounded-hook-bridge-v1",
    "bounded-hook-bridge-muse-v1",
];

/// A frozen `caller` whose native runtime is a real three-byte file, so the
/// durable copy under the Guard home can be published. Returns the stamp and
/// the copy's path.
fn frozen_with_runtime(home: &Home) -> (Value, String) {
    let runtime = home.root.join("bundle").join("hol-guard-runtime");
    fs::create_dir_all(runtime.parent().unwrap()).unwrap();
    fs::write(&runtime, b"abc").unwrap();
    let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let mut stamp = caller(true);
    stamp["native_runtime"] =
        json!({"path": runtime, "size": 3, "sha256": sha, "features": NATIVE_FEATURES});
    let copy = home
        .guard()
        .join("native-runtime")
        .join(sha)
        .join("hol-guard-runtime");
    (stamp, copy.to_string_lossy().into_owned())
}

fn shim() -> String {
    r#"{"shim_path": "/g/bin/guard-x", "notes": ["shim note"]}"#.to_owned()
}

fn after(change: &Value) -> String {
    String::from_utf8(STANDARD.decode(change["after"].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn describe_lists_every_adapter_this_kind_owns() {
    let answer = dispatch(&json!({"op": "describe"})).unwrap();
    let names: Vec<&str> = answer["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|adapter| adapter["harness"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "devin",
            "antigravity",
            "gemini",
            "kimi",
            "openclaw",
            "paseo",
            "muse",
            "grok",
            "zcode",
            "pi",
            "omp",
            "opencode",
            "cline",
            "copilot",
            "cursor",
            "claude-code",
            "hermes",
            "codex"
        ]
    );
}

#[test]
fn describe_names_the_hermes_and_copilot_preparation_and_hook_ownership() {
    let answer = dispatch(&json!({"op": "describe"})).unwrap();
    let find = |name: &str| {
        answer["adapters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|adapter| adapter["harness"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(find("hermes")["prepare"], "unavailable");
    assert_eq!(find("devin")["prepare"], "plan");
    let copilot = find("copilot");
    assert_eq!(copilot["prepare"], "detected");
    assert_eq!(copilot["launch_op"], "launch_command");
    assert_eq!(find("grok")["launch_op"], "");
    // Cursor resolves `cursor-agent` or `cursor agent` itself.
    assert_eq!(find("cursor")["launch_op"], "launch_command");
    assert!(copilot["hook_ownership"]["message"]
        .as_str()
        .unwrap()
        .starts_with("Guard could not read which Copilot hooks"));
    assert_eq!(
        copilot["hook_ownership"]["ops"].as_array().unwrap().len(),
        7
    );
    assert_eq!(find("cursor")["hook_ownership"], Value::Null);
}

#[test]
fn kimi_install_adds_the_hook_and_keeps_shim_notes_last() {
    let home = Home::new();
    let answer = home.ask(
        "kimi",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "-m", "guard hook"]}),
    );
    let change = &answer["files"][0];
    assert_eq!(change["before"], Value::Null);
    assert_eq!(change["after_mode"], 0o644);
    assert!(after(change).contains("'guard hook'"));
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(
        manifest["notes"],
        json!([
            "Guard hook entries added to ~/.kimi-code/config.toml",
            "shim note"
        ])
    );
    let text = answer["manifest"].as_str().unwrap();
    assert!(text.find("\"shim_path\"").unwrap() < text.find("\"notes\"").unwrap());
}

#[test]
fn devin_install_backs_up_the_config_and_records_state() {
    let home = Home::new();
    let config = home.home().join(".config/devin/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "{}\n").unwrap();
    let answer = home.ask(
        "devin",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"]}),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    assert!(files[0]["path"]
        .as_str()
        .unwrap()
        .ends_with("managed/devin/config.json.backup"));
    assert_eq!(after(&files[0]), "{}\n");
    assert!(after(&files[1]).contains("/py hook"));
    for file in files {
        let path = Path::new(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
    let uninstall = home.ask("devin", "prepare_uninstall", json!({}));
    assert_eq!(uninstall["writes"].as_array().unwrap().len(), 1);
    assert!(uninstall["deletes"][0]
        .as_str()
        .unwrap()
        .ends_with("managed/devin/install.state.json"));
}

#[test]
fn apply_uninstall_runs_the_plan_it_prepares_and_journals_managed_writes() {
    let home = Home::new();
    let config = home.home().join(".config/devin/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "{}\n").unwrap();
    let install = home.ask(
        "devin",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"]}),
    );
    for file in install["files"].as_array().unwrap() {
        let path = Path::new(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
    let plan = home.ask("devin", "prepare_uninstall", json!({}));
    let state = plan["deletes"][0].as_str().unwrap().to_owned();
    let launcher = home.guard().join("bin/guard-devin");
    fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    fs::write(&launcher, "#!/bin/sh\n").unwrap();
    let applied = home.ask("devin", "apply_uninstall", json!({}));
    assert!(!launcher.exists());
    let manifest: Value = serde_json::from_str(applied["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(
        manifest["removed_paths"][0],
        json!(launcher.to_string_lossy())
    );
    assert!(applied["manifest"].is_string(), "{applied}");
    assert_eq!(
        applied["events"][0]["mutation"]["operation"],
        json!("publish")
    );
    assert!(!Path::new(&state).exists());
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        plan["writes"][0]["text"].as_str().unwrap()
    );
}

#[test]
fn muse_hook_outlasts_the_approval_wait() {
    let home = Home::new();
    let answer = home.ask("muse", "hook_spec", json!({}));
    assert_eq!(answer["timeout_seconds"], 130);
}

#[test]
fn a_config_outside_the_managed_root_is_refused() {
    let home = Home::new();
    let outside = home.root.join("elsewhere");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(home.home().join(".config")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, home.home().join(".config/devin")).unwrap();
    #[cfg(unix)]
    {
        let answer = home.ask(
            "devin",
            "prepare_install",
            json!({"shim": shim(), "hook_argv": ["x"]}),
        );
        assert_eq!(
            answer["refusal"],
            "Devin settings path escapes the managed root"
        );
    }
}

#[test]
fn openclaw_install_writes_the_bundle_and_launch_reads_it_back() {
    let home = Home::new();
    let answer = home.ask(
        "openclaw",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"]}),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    for file in files {
        assert_eq!(file["no_follow"], true);
        assert_eq!(file["after_mode"], 0o600);
    }
    let pretool: Value = serde_json::from_str(&after(&files[1])).unwrap();
    assert_eq!(pretool["command"], json!(["/py", "hook"]));
    assert_eq!(pretool["timeout_seconds"], 5);
    let root = home.guard().join("openclaw");
    fs::create_dir_all(&root).unwrap();
    for file in files {
        fs::write(file["path"].as_str().unwrap(), after(file)).unwrap();
    }
    let env = home.ask("openclaw", "launch_env", json!({}));
    assert_eq!(env["env"]["OPENCLAW_GUARD_CHANNEL_POSTURE"], "enabled");
    let probe = home.ask("openclaw", "runtime_probe", json!({}));
    assert_eq!(probe["probe"]["managed_install_ready"], true);
    assert_eq!(probe["command_argv"], Value::Null);
}

#[test]
fn openclaw_launch_env_ignores_a_manifest_naming_other_paths() {
    let home = Home::new();
    let root = home.guard().join("openclaw");
    fs::create_dir_all(&root).unwrap();
    let manifest =
        json!({"managed_overlay_path": "/tmp/x.json", "pretool_hook_path": "/tmp/y.json"});
    fs::write(root.join("manifest.json"), manifest.to_string()).unwrap();
    assert_eq!(
        home.ask("openclaw", "launch_env", json!({}))["env"],
        json!({})
    );
}

#[test]
fn openclaw_approval_flow_follows_the_managed_capabilities() {
    let home = Home::new();
    let managed =
        json!({"managed_install": {"manifest": {"capabilities": {"same_channel": true}}}});
    assert_eq!(
        home.ask("openclaw", "approval_flow", managed)["prompt_channel"],
        "native"
    );
    assert_eq!(
        home.ask("openclaw", "approval_flow", json!({}))["prompt_channel"],
        "native-fallback"
    );
}

#[test]
fn proofs_bind_and_verify_until_a_file_changes() {
    let home = Home::new();
    let config = home.home().join("settings.json");
    fs::write(&config, "{}").unwrap();
    let request = |op: &str, manifest: Value| json!({"op": op, "context": home.context(json!({})), "manifest": manifest});
    let bound = dispatch(&request("proof_bind", json!({"config_path": config}))).unwrap();
    let proof: Value = serde_json::from_str(bound["proof"].as_str().unwrap()).unwrap();
    let manifest = json!({"protection_artifact_proof": proof});
    assert_eq!(
        dispatch(&request("proof_verify", manifest.clone())).unwrap()["verified"],
        true
    );
    fs::write(&config, "{\"x\": 1}").unwrap();
    assert_eq!(
        dispatch(&request("proof_verify", manifest)).unwrap()["verified"],
        false
    );
    assert_eq!(
        dispatch(&request("proof_verify", json!({}))).unwrap()["verified"],
        Value::Null
    );
}

#[test]
fn a_relative_paseo_home_is_refused() {
    let home = Home::new();
    let answer = home.ask_env(
        "paseo",
        "policy_path",
        json!({}),
        json!({"PASEO_HOME": "rel"}),
    );
    assert_eq!(
        answer["refusal"],
        "Use an absolute PASEO_HOME on the Paseo daemon host."
    );
    let answer = home.ask_env(
        "paseo",
        "policy_path",
        json!({}),
        json!({"PASEO_HOME": "~/p"}),
    );
    assert_eq!(
        Path::new(answer["path"].as_str().unwrap()),
        home.home().join("p/config.json")
    );
}

#[cfg(unix)]
#[test]
fn paseo_refuses_a_linked_managed_directory() {
    let home = Home::new();
    let elsewhere = home.root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.guard().join("managed")).unwrap();
    let answer = home.ask("paseo", "prepare_uninstall", json!({}));
    assert!(answer["refusal"]
        .as_str()
        .unwrap()
        .starts_with("Paseo refuses a symlink in a managed path"));
}

#[test]
fn paseo_without_an_available_provider_refuses_to_install() {
    let home = Home::new();
    let delegates = json!({"claude-code": false, "codex": false, "copilot": false, "opencode": false, "pi": false, "omp": false});
    let answer = home.ask("paseo", "prepare_install", json!({"delegates": delegates}));
    assert!(answer["refusal"]
        .as_str()
        .unwrap()
        .starts_with("No supported, enabled Paseo provider runtime"));
}

#[cfg(unix)]
#[test]
fn command_lookup_follows_the_callers_path() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let bin = home.root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let gemini = bin.join("gemini");
    fs::write(&gemini, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&gemini, fs::Permissions::from_mode(0o755)).unwrap();
    let env = json!({"PATH": bin});
    let answer = home.ask_env("gemini", "resolved_executable", json!({}), env);
    assert_eq!(Path::new(answer["path"].as_str().unwrap()), gemini);
    let found = home.ask_env(
        "codex",
        "command_available",
        json!({}),
        json!({"PATH": bin}),
    );
    assert_eq!(found, json!({"available": false}));
    let found = home.ask_env(
        "gemini",
        "command_available",
        json!({}),
        json!({"PATH": bin}),
    );
    assert_eq!(found, json!({"available": true}));

    let launch = |harness: &str, workspace: Value| {
        let mut context = home.context(json!({"PATH": bin}));
        context["workspace"] = workspace;
        let extra = json!({"args": ["--flag"], "context": context});
        home.ask_env(harness, "default_launch", extra, json!({}))["argv"].clone()
    };
    let workspace = home.root.join("project");
    assert_eq!(
        launch("gemini", json!(workspace)),
        json!([gemini, "--flag"])
    );
    assert_eq!(
        launch("opencode", Value::Null),
        json!(["opencode", "--flag"])
    );
    assert_eq!(
        launch("opencode", json!(workspace)),
        json!(["opencode", workspace, "--flag"])
    );
    let request = json!({"harness": "gemini", "op": "default_launch", "context": home.context(json!({})), "args": [1]});
    assert!(dispatch(&request).is_err());
}

#[test]
fn devin_reads_its_config_from_appdata_only_on_windows() {
    let home = Home::new();
    let appdata = home.root.join("AppData").join("Roaming");
    let mut ctx = super::Ctx::parse(Some(&home.context(json!({"APPDATA": appdata})))).unwrap();
    let spec = super::describe::spec("devin").unwrap();
    let path = |ctx: &super::Ctx| {
        super::settings_hooks::dispatch(spec, "policy_path", ctx, &serde_json::Map::new())
            .ok()
            .unwrap()["path"]
            .as_str()
            .map(std::path::PathBuf::from)
            .unwrap()
    };
    ctx.windows = false;
    assert_eq!(path(&ctx), home.home().join(".config/devin/config.json"));
    ctx.windows = true;
    assert_eq!(path(&ctx), appdata.join("devin/config.json"));
}

#[cfg(unix)]
#[test]
fn a_named_user_home_expands_as_python_does() {
    let home = Home::new();
    let ctx = super::Ctx::parse(Some(&home.context(json!({})))).unwrap();
    let root = nix::unistd::User::from_name("root").unwrap().unwrap().dir;
    assert_eq!(super::kimi::expand_user(&ctx, "~root/x"), root.join("x"));
    assert_eq!(super::kimi::expand_user(&ctx, "~/x"), home.home().join("x"));
}
