//! A real Codex hook installation on disk and the manifest that describes it,
//! for the manifest-verify op's tests to change one thing at a time.

use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub(super) const EVENT_COMMAND: &str = "/guard/python -m guard hook";

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub(super) config: PathBuf,
    pub(super) bridge: PathBuf,
    pub(super) interpreter: PathBuf,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        // Identities record canonical paths, so the fixture lives under one.
        let base = fs::canonicalize(root.path()).expect("a canonical root");
        let config = base.join("config.toml");
        let bridge = base.join("bridge.py");
        let interpreter = base.join("python");
        fs::write(&config, b"[hooks]\n").expect("the config");
        fs::write(&bridge, b"print('bridge')\n").expect("the bridge");
        fs::write(&interpreter, b"#!/bin/sh\n").expect("the interpreter");
        set_mode(&config, 0o600);
        set_mode(&bridge, 0o644);
        set_mode(&interpreter, 0o755);
        Self {
            _root: root,
            config,
            bridge,
            interpreter,
        }
    }

    pub(super) fn request(&self) -> CodexHookManifestVerifyRequestV1 {
        let interpreter = self.interpreter_identity();
        let bridge = identity(&self.bridge, "bridge", false);
        let group = json!({ "hooks": [{ "type": "command", "command": EVENT_COMMAND }] });
        let bindings: Vec<Value> = MANAGED_EVENTS
            .iter()
            .map(|event| {
                json!({
                    "event": event,
                    "group": group,
                    "handler": { "type": "command", "command": EVENT_COMMAND },
                    "argv": argv(),
                    "handler_index": 0,
                    "handler_id": format!("codex:{event}:guard-handler-v1"),
                })
            })
            .collect();
        let hooks: Map<String, Value> = MANAGED_EVENTS
            .iter()
            .map(|event| ((*event).to_owned(), json!([group])))
            .collect();
        let context = json!({ "guard_home": "/guard", "home_dir": "/home", "runtime_guard_home": "/guard", "workspace_dir": null });
        let manifest = json!({
            "schema_version": 2,
            "harness": "codex",
            "config": { "scope": "global", "target": text(&self.config) },
            "context": context,
            "package_version": "1.2.3",
            "generated_at": "2026-10-27T12:00:00+00:00",
            "interpreter": interpreter,
            "packaged_files": [bridge],
            "transport": { "wrapper": null, "bridge": bridge },
            "fallback": { "argv": ["fallback"], "interpreter": interpreter, "package_roles": ["fallback_entrypoint"] },
            "daemon_start": {
                "argv": ["daemon"],
                "interpreter": interpreter,
                "package_roles": ["daemon_entrypoint", "daemon_manager"],
            },
            "events": bindings,
        });
        let canonical_paths = [&self.bridge, &self.interpreter]
            .iter()
            .map(|path| (text(path), text(path)))
            .collect();
        CodexHookManifestVerifyRequestV1 {
            schema: CODEX_HOOK_MANIFEST_VERIFY_REQUEST_SCHEMA.to_owned(),
            request_id: "r1".to_owned(),
            posix: std::env::consts::FAMILY == "unix",
            current_uid: Some(facts(&self.config).uid),
            failure: None,
            manifest: Some(manifest),
            hooks: Some(Value::Object(hooks)),
            expected: Some(CodexHookManifestExpectedV1 {
                config_path: text(&self.config),
                config_target: text(&self.config),
                context,
                package_version: "1.2.3".to_owned(),
                interpreter_path: text(&self.interpreter),
                packaged_paths: BTreeMap::from([("bridge".to_owned(), text(&self.bridge))]),
                fallback_argv: vec!["fallback".to_owned()],
                daemon_start_argv: vec!["daemon".to_owned()],
                event_bindings: bindings,
            }),
            canonical_paths,
            installed_python_package_files: Vec::new(),
            command_argvs: BTreeMap::from([(EVENT_COMMAND.to_owned(), Some(argv()))]),
            private_groups: Vec::new(),
        }
    }

    fn interpreter_identity(&self) -> Value {
        let facts = facts(&self.interpreter);
        json!({
            "role": "interpreter",
            "invocation_path": text(&self.interpreter),
            "invocation_mode": facts.mode & 0o7777,
            "invocation_owner_uid": facts.uid,
            "link_target": null,
            "target": identity(&self.interpreter, "interpreter", true),
        })
    }
}

pub(super) fn argv() -> Vec<String> {
    vec![
        "/guard/python".to_owned(),
        "-m".to_owned(),
        "guard".to_owned(),
        "hook".to_owned(),
    ]
}

pub(super) fn text(path: &Path) -> String {
    path.to_str().expect("a printable fixture path").to_owned()
}

pub(super) fn facts(path: &Path) -> FileFacts {
    FileFacts::of(path, &fs::symlink_metadata(path).expect("fixture metadata"))
}

pub(super) fn identity(path: &Path, role: &str, executable_required: bool) -> Value {
    let bytes = fs::read(path).expect("the fixture bytes");
    let facts = facts(path);
    json!({
        "role": role,
        "path": text(path),
        "sha256": hex::encode(Sha256::digest(&bytes)),
        "mode": facts.mode & 0o7777,
        "size": bytes.len(),
        "owner_uid": facts.uid,
        "executable_required": executable_required,
    })
}

/// Off POSIX a file has no mode bits to set, so the fixture keeps the
/// defaults its platform gives it.
pub(super) fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .expect("the fixture permissions");
    let _ = (path, mode);
}

pub(super) fn manifest_mut(
    request: &mut CodexHookManifestVerifyRequestV1,
) -> &mut Map<String, Value> {
    request
        .manifest
        .as_mut()
        .and_then(Value::as_object_mut)
        .expect("a manifest object")
}

pub(super) fn state(request: &CodexHookManifestVerifyRequestV1) -> Value {
    evaluate_request(request)["state"].clone()
}

pub(super) fn reason_and_status(request: &CodexHookManifestVerifyRequestV1) -> (String, String) {
    let state = state(request);
    (
        state["integrity_reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        state["integrity_status"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

pub(super) fn expect(request: &CodexHookManifestVerifyRequestV1, reason: &str, status: &str) {
    assert_eq!(
        reason_and_status(request),
        (reason.to_owned(), status.to_owned())
    );
}
