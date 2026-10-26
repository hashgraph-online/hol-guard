//! Parity of the network-upload, encoded-command and credential-exfiltration
//! leaves against recorded Python output. The fixture holds a directory tree and
//! cases whose paths carry a `{ROOT}` token; the tree is rebuilt below a fresh
//! root. The destructive-command classifier is the recorder's stand-in rule.

use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::sfrs_credential_exfil::{
    local_shell_script_payloads, shell_script_path_from_segment,
    shell_segments_contain_credential_exfiltration,
};
use crate::sfrs_encoded_commands::{contains_encoded_or_encrypted_shell_command, EncodedScan};
use crate::sfrs_encoded_payloads::{
    contains_command_substitution_decode_exec, contains_decode_primitive, decode_base64_literal,
    decode_hex_literal, decoded_shell_payloads, looks_like_read_only_shell_pipeline,
    shell_text_without_quoted_literals,
};
use crate::sfrs_interpreter_trust::{
    contains_shell_network_file_upload, curl_stdin_config_uses_file_upload,
};
use crate::sfrs_network_upload::{
    command_uses_curl_stdin_heredoc, curl_segment_reads_config_from_stdin,
    looks_like_local_stdin_source,
};
use crate::sfrs_shell_tokens::split_shell_parts;
use crate::sfrs_stdin_sources::{
    decode_shell_text_literal, echo_stdout_payload, printf_stdout_payloads,
};
use crate::sfrs_upload_arguments::{
    curl_config_arguments, curl_data_urlencode_value_uses_local_file,
    curl_form_value_uses_local_file, curl_variable_value_uses_local_file, value_uses_local_file,
    wget_segment_uses_file_upload,
};

const TOKEN: &str = "{ROOT}";
const DESTRUCTIVE_WORDS: [&str; 4] = ["rm", "shred", "mkfs", "dd"];

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn destructive(text: &str, _cwd: Option<&Path>, _home: Option<&Path>) -> bool {
    text.split_whitespace()
        .any(|word| DESTRUCTIVE_WORDS.contains(&word))
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_net.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-net-{}", std::process::id()));
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

fn optional_path(value: &Value) -> Option<PathBuf> {
    value.as_str().map(PathBuf::from)
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
    let flag = |index: usize| args[index].as_bool().expect("bool argument");
    match function {
        "contains_shell_network_file_upload" => {
            let (cwd, home, roots) = (
                optional_path(&args[1]),
                optional_path(&args[2]),
                optional_roots(&args[3]),
            );
            json!(contains_shell_network_file_upload(
                text(&args[0]),
                cwd.as_deref(),
                home.as_deref(),
                roots.as_deref(),
            ))
        }
        "contains_encoded_or_encrypted_shell_command" => {
            let (cwd, home, roots) = (
                optional_path(&args[1]),
                optional_path(&args[2]),
                optional_roots(&args[3]),
            );
            let scan = EncodedScan {
                cwd: cwd.as_deref(),
                home_dir: home.as_deref(),
                allowed_roots: roots.as_deref(),
                visited_script_paths: &[],
                destructive: &destructive,
            };
            json!(contains_encoded_or_encrypted_shell_command(
                text(&args[0]),
                &scan,
                0
            ))
        }
        "curl_stdin_config_uses_file_upload" => {
            let (cwd, home) = (optional_path(&args[1]), optional_path(&args[2]));
            let source = text(&args[0]);
            json!(curl_stdin_config_uses_file_upload(
                source,
                &parts_of(source),
                cwd.as_deref(),
                home.as_deref(),
                None,
            ))
        }
        "local_shell_script_payloads" => {
            let (cwd, home, roots) = (
                optional_path(&args[1]),
                optional_path(&args[2]),
                optional_roots(&args[3]),
            );
            let payloads = local_shell_script_payloads(
                &strings(&args[0]),
                cwd.as_deref(),
                home.as_deref(),
                roots.as_deref(),
                &[],
            );
            json!(payloads
                .into_iter()
                .map(|(body, parent, path)| json!([
                    body,
                    parent.map(|item| item.to_string_lossy().into_owned()),
                    path
                ]))
                .collect::<Vec<_>>())
        }
        "looks_like_read_only_shell_pipeline" => {
            let source = text(&args[0]);
            json!(looks_like_read_only_shell_pipeline(
                source,
                &parts_of(source),
                None,
                None,
                &destructive,
            ))
        }
        "command_uses_curl_stdin_heredoc" => json!(command_uses_curl_stdin_heredoc(text(&args[0]))),
        "shell_segments_contain_credential_exfiltration" => json!(
            shell_segments_contain_credential_exfiltration(&parts_of(text(&args[0])))
        ),
        "curl_segment_reads_config_from_stdin" => {
            json!(curl_segment_reads_config_from_stdin(&strings(&args[0])))
        }
        "wget_segment_uses_file_upload" => {
            json!(wget_segment_uses_file_upload(&strings(&args[0]), flag(1)))
        }
        "contains_command_substitution_decode_exec" => {
            json!(contains_command_substitution_decode_exec(text(&args[0])))
        }
        "contains_decode_primitive" => json!(contains_decode_primitive(text(&args[0]))),
        "shell_text_without_quoted_literals" => {
            json!(shell_text_without_quoted_literals(text(&args[0])))
        }
        "decoded_shell_payloads" => json!(decoded_shell_payloads(text(&args[0]))),
        "shell_script_path_from_segment" => {
            json!(shell_script_path_from_segment(&strings(&args[0])))
        }
        "decode_shell_text_literal" => json!(decode_shell_text_literal(text(&args[0]))),
        "decode_base64_literal" => json!(decode_base64_literal(text(&args[0]))),
        "decode_hex_literal" => json!(decode_hex_literal(text(&args[0]))),
        "curl_config_arguments" => json!(curl_config_arguments(text(&args[0]))),
        "looks_like_local_stdin_source" => json!(looks_like_local_stdin_source(text(&args[0]))),
        "value_uses_local_file" => json!(value_uses_local_file(text(&args[0]), flag(1))),
        "curl_form_value_uses_local_file" => {
            json!(curl_form_value_uses_local_file(text(&args[0])))
        }
        "curl_data_urlencode_value_uses_local_file" => {
            json!(curl_data_urlencode_value_uses_local_file(text(&args[0])))
        }
        "curl_variable_value_uses_local_file" => {
            json!(curl_variable_value_uses_local_file(text(&args[0])))
        }
        "printf_stdout_payloads" => json!(printf_stdout_payloads(&strings(&args[0]))),
        "echo_stdout_payload" => json!(echo_stdout_payload(&strings(&args[0]))),
        other => panic!("unknown recorded function {other}"),
    }
}

#[test]
fn network_upload_leaves_match_recorded_python() {
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
