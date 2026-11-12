use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{dispatch, mode_value, warning};
use crate::hermes_yaml;
use crate::runner_authority_op::ERR_INVALID;

const AUTO: &str = "providers:\n  openai-codex:\n    codeMode: auto\n";
const OFF: &str = "providers:\n  openai-codex:\n    codeMode: off\n";

fn write(path: &Path, body: &str) -> PathBuf {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, body).expect("write");
    path.to_path_buf()
}

fn spelled(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn warnings(request: Value) -> Value {
    dispatch(&request).expect("warnings")["warnings"].clone()
}

fn home_warnings(home: &Path, workspace: Option<&Path>) -> Value {
    warnings(json!({"home": spelled(home), "workspace": workspace.map(spelled)}))
}

fn warned(path: &Path) -> Value {
    json!([warning(path)])
}

fn mode(body: &str) -> Option<String> {
    mode_value(&hermes_yaml::load(body).ok()?.ok()?)
}

#[test]
fn the_mode_reads_from_the_nested_or_dotted_key() {
    assert_eq!(mode(AUTO).as_deref(), Some("auto"));
    assert_eq!(mode(OFF).as_deref(), Some("off"));
    // YAML 1.1 reads a bare `on` as a boolean.
    assert_eq!(
        mode("providers.openai-codex.codeMode: on\n").as_deref(),
        Some("on")
    );
    assert_eq!(
        mode("providers.openai-codex.codeMode: ' AUTO '\n").as_deref(),
        Some("auto")
    );
    // A null dotted key falls back to the nested one.
    let both =
        "providers.openai-codex.codeMode: null\nproviders:\n  openai-codex:\n    codeMode: auto\n";
    assert_eq!(mode(both).as_deref(), Some("auto"));
    for body in [
        "providers:\n  openai-codex:\n    other: 1\n",
        "providers:\n  openai-codex:\n    codeMode: 1\n",
        "providers: [openai-codex]\n",
        "- providers\n",
        "",
    ] {
        assert_eq!(mode(body), None, "{body:?}");
    }
}

#[test]
fn an_active_mode_warns_with_the_file_that_set_it() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    for (body, expect) in [
        (AUTO, true),
        ("providers:\n  openai-codex:\n    codeMode: on\n", true),
        (OFF, false),
        ("not: [valid\n", false),
        ("", false),
    ] {
        let config = write(&home.join(".omp/agent/config.yml"), body);
        let expected = if expect { warned(&config) } else { json!([]) };
        assert_eq!(home_warnings(home, None), expected, "{body:?}");
    }
    let empty = tempfile::tempdir().expect("tempdir");
    assert_eq!(home_warnings(empty.path(), None), json!([]));
}

#[test]
fn later_layers_override_earlier_ones() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("home");
    let workspace = directory.path().join("workspace");
    let yaml_config = write(&home.join(".omp/agent/config.yaml"), AUTO);
    assert_eq!(home_warnings(&home, None), warned(&yaml_config));
    // `config.yml` comes first and hides `config.yaml`.
    write(&home.join(".omp/agent/config.yml"), OFF);
    assert_eq!(home_warnings(&home, None), json!([]));
    let project = write(&workspace.join(".omp/config.yml"), AUTO);
    assert_eq!(home_warnings(&home, Some(&workspace)), warned(&project));
    write(&workspace.join(".omp/config.yml"), OFF);
    write(&home.join(".omp/agent/config.yml"), AUTO);
    assert_eq!(home_warnings(&home, Some(&workspace)), json!([]));
    // A project file that sets nothing leaves the user's mode in force.
    write(&workspace.join(".omp/config.yml"), "theme: dark\n");
    assert_eq!(
        home_warnings(&home, Some(&workspace)),
        warned(&home.join(".omp/agent/config.yml"))
    );
}

#[test]
fn the_agent_directory_follows_the_environment() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("home");
    let custom = write(&directory.path().join("agent/config.yml"), AUTO);
    let request =
        json!({"home": spelled(&home), "agentDir": spelled(custom.parent().expect("parent"))});
    assert_eq!(warnings(request), warned(&custom));
    let renamed = write(&home.join(".pi-alt/agent/config.yml"), AUTO);
    let request = json!({"home": spelled(&home), "configDir": ".pi-alt"});
    assert_eq!(warnings(request), warned(&renamed));
    // An empty variable counts as unset.
    let default = write(&home.join(".omp/agent/config.yml"), AUTO);
    let request = json!({"home": spelled(&home), "agentDir": "", "configDir": ""});
    assert_eq!(warnings(request), warned(&default));
}

#[test]
fn an_oversized_file_or_a_malformed_request_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path();
    let padding = format!("{AUTO}#{}\n", "x".repeat(1_000_000));
    write(&home.join(".omp/agent/config.yml"), &padding);
    assert_eq!(home_warnings(home, None), json!([]));
    for request in [
        json!({}),
        json!({"home": 1}),
        json!({"home": "/h", "workspace": 1}),
        json!({"home": "/h", "agentDir": ["/a"]}),
        json!({"home": "/h", "configDir": false}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
