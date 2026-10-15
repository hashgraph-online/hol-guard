//! Parity of the filesystem-reading SFRS helpers against recorded Python
//! output. The fixture holds a directory tree and cases whose paths carry a
//! `{ROOT}` token; the tree is rebuilt below a fresh root before replay.

use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::sfrs_source_edit::{
    bounded_edit_workspace_is_safe, bounded_in_place_sed_target, literal_sed_script_is_safe,
    literal_sed_substitution_is_safe, same_workspace_file, sed_pattern_is_literal,
    sed_replacement_is_literal, split_literal_sed_commands,
};

const TOKEN: &str = "{ROOT}";

pub(crate) struct Scratch(pub(crate) PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/fs_helpers.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

/// Rebuild the recorded tree below a fresh canonical root.
pub(crate) fn build_tree(document: &Value, label: &str) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-fs-{label}-{}", std::process::id()));
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
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), bind(root, item)))
                .collect(),
        ),
        other => other.clone(),
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

fn delimiter(value: &Value) -> char {
    text(value).chars().next().expect("delimiter")
}

fn run(function: &str, args: &[Value]) -> Option<Value> {
    Some(match function {
        "split_literal_sed_commands" => split_literal_sed_commands(text(&args[0])).into(),
        "literal_sed_script_is_safe" => literal_sed_script_is_safe(text(&args[0])).into(),
        "literal_sed_substitution_is_safe" => {
            literal_sed_substitution_is_safe(text(&args[0])).into()
        }
        "sed_pattern_is_literal" => {
            sed_pattern_is_literal(text(&args[0]), delimiter(&args[1])).into()
        }
        "sed_replacement_is_literal" => {
            sed_replacement_is_literal(text(&args[0]), delimiter(&args[1])).into()
        }
        "bounded_edit_workspace_is_safe" => {
            bounded_edit_workspace_is_safe(Path::new(text(&args[0])), Path::new(text(&args[1])))
                .into()
        }
        "bounded_in_place_sed_target" => bounded_in_place_sed_target(
            &strings(&args[0]),
            Path::new(text(&args[1])),
            Path::new(text(&args[2])),
        )
        .map_or(Value::Null, Value::from),
        "same_workspace_file" => {
            same_workspace_file(text(&args[0]), text(&args[1]), Path::new(text(&args[2]))).into()
        }
        "compound_developer_effect_graph" => crate::sfrs_developer_graph_vectors::run(args),
        other => {
            return crate::sfrs_index_vectors::run(other, args)
                .or_else(|| crate::sfrs_quote_vectors::run(other, args))
        }
    })
}

#[test]
fn filesystem_helpers_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document, "replay");
    let root = scratch.0.clone();
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let args = bind(&root, &case["args"]);
        let expected = bind(&root, &case["result"]);
        let Some(actual) = run(function, args.as_array().expect("args")) else {
            continue;
        };
        compared += 1;
        if actual != expected {
            failures.push(format!("{function} {args}: {actual} vs {expected}"));
        }
    }
    assert!(compared > 400, "too few cases: {compared}");
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}
