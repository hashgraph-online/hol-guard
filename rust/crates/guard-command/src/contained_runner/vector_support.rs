//! Shared loader for the parity vectors recorded from the original Python.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use serde_json::Value;

static COUNTER: AtomicU64 = AtomicU64::new(0);

static VECTORS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/contained_runner_vectors.v1.json"
    ))
    .expect("vectors parse")
});

pub(super) fn vectors() -> &'static Value {
    &VECTORS
}

pub(super) fn section(name: &str) -> &'static [Value] {
    vectors()[name]
        .as_array()
        .unwrap_or_else(|| panic!("missing section {name}"))
}

pub(super) fn text(value: &Value, key: &str) -> String {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing text {key}"))
        .to_owned()
}

pub(super) fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// A unique canonical workspace directory removed on drop.
pub(super) struct Workspace {
    root: PathBuf,
    pub(super) path: PathBuf,
}

impl Workspace {
    pub(super) fn new() -> Self {
        let unique = format!(
            "guard-vec-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(unique);
        let path = root.join("workspace");
        fs::create_dir_all(&path).expect("workspace");
        Self { root, path }
    }

    pub(super) fn with_fixture(fixture: &Value) -> Self {
        let workspace = Self::new();
        workspace.materialize(fixture);
        workspace
    }

    pub(super) fn text(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Replace the `{ws}` template with this workspace path.
    pub(super) fn expand(&self, template: &str) -> String {
        template.replace("{ws}", &self.text())
    }

    pub(super) fn expand_value(&self, value: &Value) -> Value {
        match value {
            Value::String(item) => Value::String(self.expand(item)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.expand_value(item)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (key.clone(), self.expand_value(item)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    pub(super) fn templatize(&self, value: &str) -> String {
        value.replace(&self.text(), "{ws}")
    }

    fn materialize(&self, fixture: &Value) {
        for item in fixture["files"].as_array().into_iter().flatten() {
            let path = self.path.join(text(item, "path"));
            fs::create_dir_all(path.parent().expect("parent")).expect("parent dirs");
            fs::write(&path, text(item, "text")).expect("write fixture");
            if item["exec"] == Value::Bool(true) {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
            }
        }
        for item in fixture["links"].as_array().into_iter().flatten() {
            let path = self.path.join(text(item, "path"));
            fs::create_dir_all(path.parent().expect("parent")).expect("parent dirs");
            symlink(text(item, "target"), &path).expect("symlink");
        }
        for item in fixture["hardlinks"].as_array().into_iter().flatten() {
            let path = self.path.join(text(item, "path"));
            fs::create_dir_all(path.parent().expect("parent")).expect("parent dirs");
            fs::hard_link(self.path.join(text(item, "to")), &path).expect("hard link");
        }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Resolve a case's fixture reference through the shared fixture table.
pub(super) fn fixture_of(case: &Value) -> &'static Value {
    match &case["fixture"] {
        Value::String(key) => &vectors()["fixtures"][key.as_str()],
        _ => panic!("fixture must be an interned key"),
    }
}
