//! Parity of the destructive-shell and sensitive-read-pipeline leaves against
//! recorded Python output. The fixture holds a directory tree and cases whose
//! paths carry a `{ROOT}` token; the tree is rebuilt below a fresh root.

use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::sfrs_destructive::{
    contains_destructive_git_command, contains_mutating_shell_redirection,
    contains_shell_credential_exfiltration, find_command_uses_delete, find_segment_uses_delete,
    git_clean_is_preview, redacted_shell_text_for_command_names,
    segment_uses_destructive_git_command, shell_command_names, shell_text_for_redirection_scan,
};
use crate::sfrs_sensitive_pipeline::{
    curl_segment_consumes_stdin, find_segment_expects_exec_terminator,
    shell_pipeline_reads_sensitive_path_to_network, shell_segment_network_sink_receives_pipeline,
    ssh_segment_consumes_stdin, wget_segment_consumes_stdin,
};
use crate::sfrs_shell_tokens::split_shell_parts;

const TOKEN: &str = "{ROOT}";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_destructive.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-destructive-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    for name in tree["dirs"].as_array().expect("dirs") {
        fs::create_dir_all(root.join(name.as_str().expect("dir"))).expect("dir");
    }
    for (name, text) in tree["files"].as_object().expect("files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(path, text.as_str().expect("text")).expect("file");
    }
    for (name, target) in tree["links"].as_object().expect("links") {
        symlink(target.as_str().expect("target"), root.join(name)).expect("link");
    }
    Scratch(root)
}

fn bind(root: &Path, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(TOKEN, &root.to_string_lossy())),
        Value::Array(items) => items.iter().map(|item| bind(root, item)).collect(),
        other => other.clone(),
    }
}

fn unbind(root: &Path, value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(&*root.to_string_lossy(), TOKEN)),
        Value::Array(items) => items.into_iter().map(|item| unbind(root, item)).collect(),
        other => other,
    }
}

fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list argument")
        .iter()
        .map(|item| text(item).to_owned())
        .collect()
}

fn optional_roots(value: &Value) -> Option<Vec<PathBuf>> {
    value
        .as_array()
        .map(|items| items.iter().map(|item| PathBuf::from(text(item))).collect())
}

fn parts_of(source: &str) -> Vec<String> {
    if source.trim().is_empty() {
        Vec::new()
    } else {
        split_shell_parts(source)
    }
}

fn replay(function: &str, args: &[Value]) -> Value {
    let parts = || parts_of(text(&args[0]));
    match function {
        "contains_shell_credential_exfiltration" => {
            let roots = optional_roots(&args[3]);
            json!(contains_shell_credential_exfiltration(
                text(&args[0]),
                Some(Path::new(text(&args[1]))),
                Some(Path::new(text(&args[2]))),
                roots.as_deref(),
                0,
                &[],
            ))
        }
        "shell_pipeline_reads_sensitive_path_to_network" => {
            json!(shell_pipeline_reads_sensitive_path_to_network(
                &parts(),
                Some(Path::new(text(&args[1]))),
                Some(Path::new(text(&args[2]))),
            ))
        }
        "find_command_uses_delete" => json!(find_command_uses_delete(&parts())),
        "contains_destructive_git_command" => json!(contains_destructive_git_command(&parts())),
        "contains_mutating_shell_redirection" => {
            json!(contains_mutating_shell_redirection(&parts()))
        }
        "shell_command_names" => json!(shell_command_names(text(&args[0]))),
        "redacted_shell_text_for_command_names" => {
            json!(redacted_shell_text_for_command_names(text(&args[0])))
        }
        "shell_text_for_redirection_scan" => {
            json!(shell_text_for_redirection_scan(text(&args[0])))
        }
        "git_clean_is_preview" => json!(git_clean_is_preview(&strings(&args[0]))),
        "segment_uses_destructive_git_command" => {
            json!(segment_uses_destructive_git_command(&strings(&args[0])))
        }
        "curl_segment_consumes_stdin" => json!(curl_segment_consumes_stdin(&strings(&args[0]))),
        "wget_segment_consumes_stdin" => json!(wget_segment_consumes_stdin(&strings(&args[0]))),
        "ssh_segment_consumes_stdin" => json!(ssh_segment_consumes_stdin(&strings(&args[0]))),
        "find_segment_uses_delete" => json!(find_segment_uses_delete(&strings(&args[0]))),
        "find_segment_expects_exec_terminator" => {
            json!(find_segment_expects_exec_terminator(&strings(&args[0])))
        }
        "shell_segment_network_sink_receives_pipeline" => {
            json!(shell_segment_network_sink_receives_pipeline(&strings(
                &args[0]
            )))
        }
        other => panic!("unknown recorded function {other}"),
    }
}

#[test]
fn destructive_shell_leaves_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.as_path();
    let mut failures = Vec::new();
    let cases = document["cases"].as_array().expect("cases");
    for case in cases {
        let function = text(&case["fn"]);
        let args: Vec<Value> = case["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|item| bind(root, item))
            .collect();
        let actual = unbind(root, replay(function, &args));
        if actual != case["result"] {
            failures.push(format!(
                "{function} {} => {actual}, expected {}",
                case["args"], case["result"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases diverge:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
