//! A package manager that is itself a Node script (npm, pnpm and yarn through
//! corepack all are) launches under the caller's `NODE_OPTIONS`. A value that
//! only sizes the heap, which agent wrappers commonly export, must leave the
//! context reusable; anything that can load code must not.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{build_package_execution_context, BuildInput, BuiltContext};

const PNPM_LOCK: &str = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\n";
const PACKAGE_JSON: &str = "{\"name\": \"app\", \"dependencies\": {}}\n";

fn executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Lab {
    root: tempfile::TempDir,
}

impl Lab {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        // The interpreter has to be a native binary for the entrypoint to be
        // read at all; any one stands in for `node` here.
        let native = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .unwrap();
        std::fs::copy(native, bin.join("node")).unwrap();
        executable(&bin.join("pnpm"), "#!/usr/bin/env node\n// pnpm\n");
        std::fs::create_dir_all(root.path().join("home")).unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        std::fs::write(
            workspace.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://github.com/example/app.git\n",
        )
        .unwrap();
        std::fs::write(workspace.join("package.json"), PACKAGE_JSON).unwrap();
        std::fs::write(workspace.join("pnpm-lock.yaml"), PNPM_LOCK).unwrap();
        Self { root }
    }

    fn context(&self, node_options: Option<&str>) -> BuiltContext {
        let root = self.root.path();
        let workspace = root.join("workspace");
        let home = root.join("home");
        let bin = root.join("bin");
        let mut environment = BTreeMap::from([
            ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
            ("PATH".to_owned(), bin.to_str().unwrap().to_owned()),
        ]);
        if let Some(value) = node_options {
            environment.insert("NODE_OPTIONS".to_owned(), value.to_owned());
        }
        let metadata: Map<String, Value> = serde_json::from_value(json!({
            "package_manager": "pnpm",
            "intent_kind": "install",
            "flags": ["--frozen-lockfile"],
        }))
        .unwrap();
        build_package_execution_context(&BuildInput {
            workspace_dir: workspace.to_str().unwrap(),
            metadata: &metadata,
            executable: Some("pnpm"),
            executable_args: &["install".to_owned(), "--frozen-lockfile".to_owned()],
            environment: &environment,
            process_cwd: workspace.to_str().unwrap(),
            process_home: home.to_str().unwrap(),
            process_home_env: home.to_str(),
            process_path: bin.to_str(),
        })
        .unwrap()
    }
}

fn executable_digest(context: &BuiltContext) -> String {
    context
        .components
        .iter()
        .find(|component| component.name == "package_manager_executable")
        .unwrap()
        .digest
        .clone()
}

#[test]
fn a_heap_size_node_options_keeps_a_node_script_manager_reusable() {
    let lab = Lab::new();
    let first = lab.context(Some("--max-old-space-size=12288"));
    let second = lab.context(Some("--max-old-space-size=12288"));

    assert!(first.portable, "{:?}", first.non_portable_reason);
    assert_eq!(executable_digest(&first), executable_digest(&second));
    assert_eq!(first.digest, second.digest);
}

#[test]
fn a_heap_size_node_options_matches_the_launch_without_one() {
    let lab = Lab::new();
    let without = lab.context(None);
    let with = lab.context(Some("--max-old-space-size=8192 --no-warnings"));

    assert!(without.portable, "{:?}", without.non_portable_reason);
    assert_eq!(executable_digest(&without), executable_digest(&with));
}

#[test]
fn a_code_loading_node_options_still_leaves_the_launch_unproven() {
    let lab = Lab::new();
    for value in [
        "--require ./preload.js",
        "--import=./preload.mjs",
        "--max-old-space-size=8192 --require ./preload.js",
        "--inspect",
    ] {
        let context = lab.context(Some(value));
        assert!(!context.portable, "{value}");
        assert_eq!(
            context.non_portable_reason.as_deref(),
            Some("package_manager_launch_identity_unavailable"),
            "{value}"
        );
    }
}

