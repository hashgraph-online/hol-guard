//! The `harness_adapter` kind against throwaway homes: each op as the
//! Python adapter it replaces answered it.

use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use tempfile::TempDir;

use super::dispatch;

#[path = "tests_cline.rs"]
mod cline_family;
#[path = "tests_grok_zcode.rs"]
mod grok_zcode;
#[path = "tests_opencode.rs"]
mod opencode_family;
#[path = "tests_pi.rs"]
mod pi_family;

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

    fn context(&self, env: Value) -> Value {
        json!({
            "home": self.home(),
            "workspace": null,
            "guard_home": self.guard(),
            "home_override_explicit": false,
            "cwd": self.root,
            "user_home": self.home(),
            "env": env,
        })
    }

    fn ask(&self, harness: &str, op: &str, extra: Value) -> Value {
        self.ask_env(harness, op, extra, json!({"PATH": ""}))
    }

    fn ask_env(&self, harness: &str, op: &str, extra: Value, env: Value) -> Value {
        let mut request = json!({"harness": harness, "op": op, "context": self.context(env)});
        for (key, value) in extra.as_object().unwrap() {
            request[key] = value.clone();
        }
        dispatch(&request).unwrap()
    }
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
            "cline"
        ]
    );
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
