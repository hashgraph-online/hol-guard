use std::cell::RefCell;

use serde_json::{json, Value};

use super::*;

fn request(subject: Value) -> ConsumerTokenRequest {
    serde_json::from_value(json!({
        "subject": subject,
        "launch_cwd": "/work/./repo",
        "cwd": "/work/repo",
        "workspace": null,
        "launch_env": {"PATH": "/usr/bin"},
        "detector_telemetry": null,
        "policy": {"current_action": "review", "mode": "prompt"},
        "sandbox_analysis": "auto",
        "extension_control_digest": "ext-digest",
    }))
    .expect("request")
}

fn artifact(overrides: Value) -> Value {
    let mut artifact = json!({
        "artifact_id": "codex:project:server",
        "name": "server",
        "artifact_type": "mcp_server",
        "harness": "codex",
        "publisher": null,
        "source_scope": "project",
        "config_path": "/work/repo/.codex/config.toml",
        "command": " ./server ",
        "args": ["--stdio"],
        "url": null,
        "transport": "stdio",
        "metadata": {"env_keys": ["TOKEN"]},
    });
    for (key, value) in overrides.as_object().expect("overrides") {
        artifact[key] = value.clone();
    }
    json!({
        "kind": "artifact",
        "artifact": artifact,
        "detection_harness": "codex",
        "command_available": true,
        "installed": true,
        "content_hash": "sha256:content",
        "capability_snapshot": {"network": false},
    })
}

/// Records each launch request and answers a fixed identity.
fn compose(request: &ConsumerTokenRequest) -> (ContextDigestComponentsV1, Vec<Value>) {
    let seen = RefCell::new(Vec::new());
    let launch = |launch: &LaunchRequest<'_>| {
        seen.borrow_mut().push(json!({
            "command": launch.command,
            "args": launch.args,
            "structured_command": launch.structured_command,
            "cwd": launch.cwd,
            "launch_env": launch.launch_env,
        }));
        json!({
            "argv_sha256": "argv",
            "entrypoint": {"status": "none"},
            "launch_cwd": "/work/repo",
            "executable": {"path": "/work/repo/server"},
            "extra": "ignored",
        })
    };
    let components = components(request, &launch).expect("components");
    (components, seen.into_inner())
}

#[test]
fn detected_artifact_binds_its_launch_content_and_capabilities() {
    let (components, launches) = compose(&request(artifact(json!({}))));
    assert_eq!(
        launches,
        vec![json!({
            "command": " ./server ",
            "args": ["--stdio"],
            "structured_command": true,
            "cwd": "/work/./repo",
            "launch_env": {"PATH": "/usr/bin"},
        })]
    );
    assert_eq!(
        components.identity,
        json!({
            "artifact_id": "codex:project:server",
            "artifact_name": "server",
            "artifact_type": "mcp_server",
            "config_path": "/work/repo/.codex/config.toml",
            "cwd": "/work/repo",
            "detection_harness": "codex",
            "executable": {
                "requested": "./server",
                "argv_sha256": "argv",
                "entrypoint": {"status": "none"},
                "launch_cwd": "/work/repo",
                "resolved": {"path": "/work/repo/server"},
            },
            "harness": "codex",
            "publisher": null,
            "source_scope": "project",
            "workspace": null,
        })
    );
    assert_eq!(
        components.content,
        json!({
            "args": ["--stdio"],
            "artifact_hash": "sha256:content",
            "command": " ./server ",
            "metadata": {"env_keys": ["TOKEN"]},
            "url": null,
        })
    );
    assert_eq!(
        components.capabilities,
        json!({
            "artifact_capabilities": {"network": false},
            "command_available": true,
            "installed": true,
            "runtime_detectors": {"failures": [], "ran": false},
            "scanner_policy_version": "consumer-evaluation-v1",
            "transport": "stdio",
        })
    );
    assert_eq!(
        components.policy,
        json!({"current_action": "review", "mode": "prompt"})
    );
    assert_eq!(
        components.sandbox,
        json!({"analysis": "auto", "required": false})
    );
    assert_eq!(components.extension_control_digest, "ext-digest");
}

#[test]
fn codex_hook_binds_its_identity_instead_of_a_launch() {
    let hook = artifact(json!({
        "artifact_type": "hook",
        "source_scope": "global",
        "metadata": {"codex_hook_identity": "hook-id", "other": 1},
    }));
    let (components, launches) = compose(&request(hook));
    assert!(launches.is_empty());
    assert_eq!(components.identity["codex_hook_identity"], "hook-id");
    assert_eq!(components.identity["config_path"], "codex-hook://global");
    assert_eq!(
        components.identity["executable"],
        json!({"codex_hook_identity": "hook-id"})
    );
    assert_eq!(
        components.content,
        json!({
            "artifact_hash": "sha256:content",
            "codex_hook_identity": "hook-id",
            "metadata": {"codex_hook_identity_schema": null, "codex_hook_identity": "hook-id"},
        })
    );
}

#[test]
fn hook_without_identity_or_from_another_harness_launches_normally() {
    for overrides in [
        json!({"artifact_type": "hook", "metadata": {"codex_hook_identity": ""}}),
        json!({"artifact_type": "hook", "harness": "claude-code", "metadata": {"codex_hook_identity": "x"}}),
    ] {
        let (components, launches) = compose(&request(artifact(overrides)));
        assert_eq!(launches.len(), 1);
        assert_eq!(launches[0]["structured_command"], false);
        assert!(components.identity.get("codex_hook_identity").is_none());
    }
}

#[test]
fn prompt_request_drops_rendering_fields_from_its_metadata() {
    let prompt = artifact(json!({
        "artifact_type": "prompt_request",
        "metadata": {"prompt_display_text": "x", "request_summary": "y", "path": "/p"},
    }));
    let (components, _) = compose(&request(prompt));
    assert_eq!(components.content["metadata"], json!({"path": "/p"}));
}

#[test]
fn detector_state_lists_each_unfinished_detector() {
    let mut request = request(artifact(json!({})));
    request.detector_telemetry = Some(vec![
        json!({"detector_id": "a", "status": "ok"}),
        json!({"detector_id": "b", "error_type": "Timeout", "status": "timeout"}),
        json!({"detector_id": "c"}),
        json!("not a record"),
    ]);
    let (components, _) = compose(&request);
    assert_eq!(
        components.capabilities["runtime_detectors"],
        json!({
            "failures": [
                {"detector_id": "b", "error_type": "Timeout", "status": "timeout"},
                {"detector_id": "c", "error_type": null, "status": null},
            ],
            "ran": true,
        })
    );
}

#[test]
fn removed_artifact_binds_its_stored_snapshot() {
    let previous = json!({
        "name": "server",
        "artifact_type": "mcp_server",
        "config_path": "/c",
        "source_scope": "project",
        "command": "node",
        "publisher": 7,
    });
    let mut request = request(json!({
        "kind": "removed",
        "harness": "codex",
        "artifact_id": "codex:project:server",
        "previous": previous,
        "previous_hash": "sha256:old",
        "args": ["index.js", "1"],
    }));
    request.policy = json!({"current_action": "sandbox-required"});
    request.workspace = Some("/work/repo".to_owned());
    let (components, launches) = compose(&request);
    assert_eq!(launches[0]["command"], "node");
    assert_eq!(launches[0]["args"], json!(["index.js", "1"]));
    assert_eq!(launches[0]["structured_command"], true);
    assert_eq!(
        components.identity,
        json!({
            "artifact_id": "codex:project:server",
            "artifact_name": "server",
            "artifact_type": "mcp_server",
            "config_path": "/c",
            "cwd": "/work/repo",
            "executable": {
                "requested": "node",
                "argv_sha256": "argv",
                "entrypoint": {"status": "none"},
                "launch_cwd": "/work/repo",
                "resolved": {"path": "/work/repo/server"},
            },
            "harness": "codex",
            "publisher": null,
            "source_scope": "project",
            "workspace": "/work/repo",
        })
    );
    assert_eq!(
        components.content,
        json!({"artifact_hash": "sha256:old", "removed": true, "snapshot": previous})
    );
    assert_eq!(
        components.capabilities,
        json!({
            "removed": true,
            "runtime_detectors": {"failures": [], "ran": false},
            "snapshot": previous,
        })
    );
    assert_eq!(components.sandbox["required"], true);
}

#[test]
fn removed_snapshot_without_a_text_command_launches_nothing_named() {
    let request = request(json!({
        "kind": "removed",
        "harness": "codex",
        "artifact_id": "a",
        "previous": {"command": ["node"]},
        "previous_hash": "h",
        "args": [],
    }));
    let (components, launches) = compose(&request);
    assert_eq!(launches[0]["command"], Value::Null);
    assert_eq!(components.identity["executable"]["requested"], Value::Null);
    assert_eq!(components.identity["artifact_type"], Value::Null);
}

#[test]
fn request_shape_is_exact() {
    let mut fields = json!({
        "subject": artifact(json!({})),
        "launch_cwd": "/w",
        "cwd": "/w",
        "workspace": null,
        "launch_env": {},
        "detector_telemetry": null,
        "policy": {},
        "sandbox_analysis": null,
        "extension_control_digest": "d",
    });
    assert!(serde_json::from_value::<ConsumerTokenRequest>(fields.clone()).is_ok());
    fields["extra"] = json!(1);
    assert!(serde_json::from_value::<ConsumerTokenRequest>(fields.clone()).is_err());
    fields.as_object_mut().expect("object").remove("extra");
    fields["subject"]["kind"] = json!("unknown");
    assert!(serde_json::from_value::<ConsumerTokenRequest>(fields).is_err());
    assert_eq!(consumer_token(&json!({})), Err(ERR_INPUT));
}

#[test]
fn artifact_without_metadata_or_args_is_rejected() {
    let launch = |_: &LaunchRequest<'_>| json!({});
    let no_metadata = request(artifact(json!({"metadata": null})));
    assert_eq!(components(&no_metadata, &launch).err(), Some(ERR_INPUT));
    let no_args = request(artifact(json!({"args": null})));
    assert_eq!(components(&no_args, &launch).err(), Some(ERR_INPUT));
}

#[test]
fn launch_identity_missing_a_binding_field_is_rejected() {
    let launch = |_: &LaunchRequest<'_>| json!({"argv_sha256": "a"});
    let detected = request(artifact(json!({})));
    assert_eq!(components(&detected, &launch).err(), Some(ERR_INPUT));
}
