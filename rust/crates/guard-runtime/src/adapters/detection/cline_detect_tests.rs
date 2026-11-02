//! Cases the recorded vectors cannot hold: a request the resident must refuse,
//! a name no JSON fixture can spell, and the private metadata the managed
//! proxy install reads. The recorded Cline cases replay in
//! `adapter_vectors_tests.rs`.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

use serde_json::{json, Value};

use crate::adapter_inventory::ERR_NAME;
use crate::cline_detect::detect;
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::pi_vectors_tests::release;
use crate::runner_authority_op::ERR_INVALID;

const SETTINGS: &str = ".cline/data/settings/cline_mcp_settings.json";
const EXTENSION_PREFIX: &[u8] = b"saoudrizwan.claude-dev-";

fn request(home: &Path, settings: &[&str]) -> Value {
    json!({
        "harness": "cline",
        "home": home.to_string_lossy(),
        "workspace": null,
        "mcp_settings": settings,
    })
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// Creates the directory `parent/<prefix><0xff>`; false when the filesystem
/// refuses a name that is not UTF-8 (macOS answers `EILSEQ`).
fn undecodable_dir(parent: &Path, prefix: &[u8]) -> bool {
    let mut name = prefix.to_vec();
    name.push(0xff);
    fs::create_dir_all(parent.join(OsString::from_vec(name))).is_ok()
}

#[test]
fn mcp_settings_must_be_an_array_of_clean_strings() {
    let root = temp_home("cline-settings-shape");
    let home = root.to_string_lossy().into_owned();
    let valid = request(&root, &[]);
    assert!(detect(&valid).is_ok());
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("mcp_settings");
    assert_eq!(detect(&missing), Err(ERR_INVALID));
    for settings in [
        json!(null),
        json!({}),
        json!(format!("{home}/settings.json")),
        json!([1]),
        json!([null]),
        json!([format!("{home}/a\0b.json")]),
        // A relative path has no base without a `cwd`.
        json!(["settings.json"]),
    ] {
        let mut args = valid.clone();
        args["mcp_settings"] = settings.clone();
        assert_eq!(detect(&args), Err(ERR_INVALID), "mcp_settings={settings}");
    }
    let mut relative = valid.clone();
    relative["mcp_settings"] = json!(["settings.json"]);
    relative["cwd"] = json!(home);
    assert!(detect(&relative).is_ok(), "a relative path reads from cwd");
    release(&root);
}

#[test]
fn an_mcp_artifact_keeps_the_raw_arguments_and_environment_privately() {
    let root = temp_home("cline-private-metadata");
    write(
        &root.join(SETTINGS),
        r#"{"mcpServers": {"s": {
            "command": "npx",
            "args": ["--token=abc123", "plain", 7],
            "env": {"API_KEY": "sk-secret", "COUNT": 3}
        }}}"#,
    );
    let settings = root.join(SETTINGS).to_string_lossy().into_owned();
    let answer = detect(&request(&root, &[settings.as_str()])).unwrap();
    release(&root);
    let artifact = &answer["artifacts"][0];
    assert_eq!(artifact["args"], json!(["--token=*****", "plain"]));
    assert_eq!(
        artifact["runtime_private_metadata"],
        json!({
            "mcp_args": ["--token=abc123", "plain"],
            "mcp_env": {"API_KEY": "sk-secret"},
        })
    );
    // The redacted fields, which Python hashes and persists, hold neither.
    let public = json!([artifact["args"], artifact["metadata"]]).to_string();
    for secret in ["abc123", "sk-secret"] {
        assert!(!public.contains(secret), "{secret} leaked: {public}");
    }
}

#[test]
fn a_non_utf8_vscode_extension_name_is_refused() {
    let root = temp_home("cline-vscode-name");
    let extensions = root.join(".vscode/extensions");
    let created = undecodable_dir(&extensions, EXTENSION_PREFIX);
    let result = detect(&request(&root, &[]));
    release(&root);
    if created {
        assert_eq!(result, Err(ERR_NAME));
    }
}

#[test]
fn a_non_utf8_name_that_is_not_a_cline_extension_is_ignored() {
    let root = temp_home("cline-vscode-other-name");
    let extensions = root.join(".vscode/extensions");
    let created = undecodable_dir(&extensions, b"other.extension-");
    let result = detect(&request(&root, &[]));
    release(&root);
    if created {
        assert_eq!(result.unwrap()["artifacts"], json!([]));
    }
}

#[test]
fn a_non_utf8_jetbrains_plugin_name_is_refused_only_when_it_names_cline() {
    let root = temp_home("cline-jetbrains-name");
    let plugins = root.join(".config/JetBrains/IntelliJIdea2025.1/plugins");
    let created = undecodable_dir(&plugins, b"other-plugin-");
    let unrelated = detect(&request(&root, &[]));
    let named = undecodable_dir(&plugins, b"cline-");
    let cline = detect(&request(&root, &[]));
    release(&root);
    if created {
        assert_eq!(unrelated.unwrap()["artifacts"], json!([]));
    }
    if named {
        assert_eq!(cline, Err(ERR_NAME));
    }
}

#[test]
fn a_non_utf8_jetbrains_ide_name_is_refused_when_a_cline_plugin_sits_under_it() {
    let root = temp_home("cline-jetbrains-ide-name");
    let roots = root.join(".config/JetBrains");
    if !undecodable_dir(&roots, b"IntelliJIdea-") {
        release(&root);
        return;
    }
    let ide = fs::read_dir(roots.as_path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::create_dir_all(ide.join("plugins/cline")).unwrap();
    let result = detect(&request(&root, &[]));
    release(&root);
    assert_eq!(result, Err(ERR_NAME));
}
