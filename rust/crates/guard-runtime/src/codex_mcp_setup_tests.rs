//! Setup and rollback against an in-memory Codex config host.

use std::path::PathBuf;

use super::*;

struct FakeHost {
    path: String,
    config: Value,
    version: u64,
    reads: usize,
    writes: Vec<Value>,
    corrupt_verification: bool,
    change_before_write: bool,
    drop_write_reply: bool,
    payload: Option<Value>,
}

impl FakeHost {
    fn new() -> Self {
        let path: PathBuf = std::env::temp_dir().join("config.toml");
        Self {
            path: path.to_string_lossy().into_owned(),
            config: json!({
                "model": "untouched",
                "mcp_servers": {"existing": {"url": "https://example.test/existing"}},
            }),
            version: 1,
            reads: 0,
            writes: Vec::new(),
            corrupt_verification: false,
            change_before_write: false,
            drop_write_reply: false,
            payload: None,
        }
    }

    fn payload_now(&self) -> Value {
        json!({"layers": [{
            "name": {"type": "user", "file": self.path, "profile": null},
            "version": self.version.to_string(),
            "config": self.config,
        }]})
    }

    fn servers(&self) -> &Map<String, Value> {
        self.config["mcp_servers"].as_object().expect("servers")
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

impl ConfigHost for FakeHost {
    fn request(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason> {
        if method == "config/read" {
            self.reads += 1;
            if self.corrupt_verification && self.reads == 2 {
                return Ok(object(json!({"layers": []})));
            }
            return Ok(object(
                self.payload.clone().unwrap_or_else(|| self.payload_now()),
            ));
        }
        assert_eq!(method, "config/batchWrite");
        assert_eq!(params["filePath"], json!(self.path));
        assert_eq!(params["reloadUserConfig"], json!(false));
        if self.change_before_write {
            self.version += 1;
            self.config["user_edit"] = json!("preserved");
            self.change_before_write = false;
        }
        if params["expectedVersion"] != json!(self.version.to_string()) {
            return Err(CHANGED);
        }
        let edits = params["edits"].as_array().expect("edits");
        assert_eq!(edits.len(), 1);
        let key = edits[0]["keyPath"].as_str().expect("key");
        assert_eq!(edits[0]["mergeStrategy"], json!("replace"));
        let name = key.strip_prefix("mcp_servers.").expect("prefix");
        self.writes.push(params.clone());
        let servers = self.config["mcp_servers"].as_object_mut().expect("servers");
        if edits[0]["value"].is_null() {
            servers.remove(name);
        } else {
            servers.insert(name.to_owned(), edits[0]["value"].clone());
        }
        self.version += 1;
        if self.drop_write_reply {
            return Err("codex_config_rpc_timeout");
        }
        Ok(object(json!({
            "status": "ok",
            "filePath": self.path,
            "version": self.version.to_string(),
        })))
    }
}

fn install_entry(
    host: &mut FakeHost,
    name: &str,
    entry: &Value,
) -> Result<Receipt, InstallFailure> {
    install(host, name, entry, &entry.to_string())
}

fn expected_versions(host: &FakeHost) -> Vec<String> {
    host.writes
        .iter()
        .map(|write| {
            write["expectedVersion"]
                .as_str()
                .expect("version")
                .to_owned()
        })
        .collect()
}

#[test]
fn setup_and_rollback_only_edit_the_reviewed_connection() {
    let mut host = FakeHost::new();
    let before = host.config.clone();
    let entry = json!({"url": "https://example.test/reviewed"});

    let receipt = install_entry(&mut host, "reviewed", &entry).expect("installed");

    assert_eq!(receipt.version, "2");
    assert_eq!(receipt.previous_version.as_deref(), Some("1"));
    assert_eq!(receipt.file_path, host.path);
    assert_eq!(host.config["model"], before["model"]);
    assert_eq!(
        host.config["mcp_servers"]["existing"],
        before["mcp_servers"]["existing"]
    );
    assert_eq!(rollback(&mut host, &receipt, &entry), Ok("3".to_owned()));
    assert_eq!(host.config, before);
    assert_eq!(expected_versions(&host), ["1", "2"]);
}

#[test]
fn existing_connection_including_null_metadata_is_never_replaced() {
    let mut host = FakeHost::new();
    host.config["mcp_servers"]["reviewed"] = Value::Null;

    let error = install_entry(
        &mut host,
        "reviewed",
        &json!({"url": "https://example.test"}),
    )
    .expect_err("refused");

    assert_eq!(error.reason, EXISTS);
    assert!(host.writes.is_empty());
}

#[test]
fn invalid_host_layers_have_safe_distinct_reasons_before_any_write() {
    let cases = [
        ("malformed_layers", "codex_config_layers_unavailable"),
        ("no_layers", "codex_config_no_layers"),
        ("malformed_layer", "codex_config_invalid_layer"),
        ("invalid_servers", "codex_config_invalid_servers"),
        ("no_user", "codex_config_no_user_layer"),
        ("multiple_users", "codex_config_multiple_user_layers"),
        ("invalid_version", "codex_config_invalid_user_version"),
        ("long_version", "codex_config_invalid_user_version"),
        ("invalid_path", "codex_config_invalid_user_path"),
        ("relative_path", "codex_config_invalid_user_path"),
        ("disabled", "codex_config_user_layer_disabled"),
        ("too_many_layers", "codex_config_layers_unavailable"),
        ("profile_layer_only", "codex_config_no_user_layer"),
    ];
    for (case, reason) in cases {
        let mut host = FakeHost::new();
        let before = host.config.clone();
        let mut payload = host.payload_now();
        match case {
            "malformed_layers" => payload["layers"] = json!("private configuration"),
            "no_layers" => payload["layers"] = json!([]),
            "malformed_layer" => payload["layers"][0]["config"] = json!("private configuration"),
            "invalid_servers" => {
                payload["layers"][0]["config"]["mcp_servers"] = json!("private configuration");
            }
            "no_user" => payload["layers"][0]["name"]["type"] = json!("project"),
            "multiple_users" => {
                let layer = payload["layers"][0].clone();
                payload["layers"]
                    .as_array_mut()
                    .expect("layers")
                    .push(layer);
            }
            "invalid_version" => payload["layers"][0]["version"] = json!({"private": "x"}),
            "long_version" => payload["layers"][0]["version"] = json!("v".repeat(257)),
            "invalid_path" => payload["layers"][0]["name"]["file"] = json!(42),
            "relative_path" => payload["layers"][0]["name"]["file"] = json!("private/config.toml"),
            "disabled" => payload["layers"][0]["disabledReason"] = json!("private configuration"),
            "too_many_layers" => {
                let layer = payload["layers"][0].clone();
                payload["layers"] = Value::Array(vec![layer; 33]);
            }
            "profile_layer_only" => payload["layers"][0]["name"]["profile"] = json!("work"),
            _ => unreachable!(),
        }
        host.payload = Some(payload);

        let error = install_entry(
            &mut host,
            "reviewed",
            &json!({"url": "https://example.test"}),
        )
        .expect_err("refused");

        assert_eq!(error.reason, reason, "{case}");
        assert!(error.chain.is_none(), "{case}");
        assert!(host.writes.is_empty(), "{case}");
        assert_eq!(host.config, before, "{case}");
    }
}

#[test]
fn a_user_layer_with_a_null_profile_or_no_profile_key_is_the_user_layer() {
    let mut host = FakeHost::new();
    let mut payload = host.payload_now();
    payload["layers"][0]["name"]
        .as_object_mut()
        .expect("name")
        .remove("profile");
    host.payload = Some(payload);

    let layers = read_layers(&mut host).expect("layers");

    assert_eq!(layers.user_version(), "1");
}

#[test]
fn setup_version_conflict_preserves_concurrent_user_edits() {
    let mut host = FakeHost::new();
    host.change_before_write = true;

    let error = install_entry(
        &mut host,
        "reviewed",
        &json!({"url": "https://example.test"}),
    )
    .expect_err("conflict");

    assert_eq!(error.reason, CHANGED);
    assert!(host.writes.is_empty());
    assert_eq!(host.config["user_edit"], json!("preserved"));
    assert!(!host.servers().contains_key("reviewed"));
}

#[test]
fn uncertain_write_is_not_replayed_or_removed_without_a_version_receipt() {
    let mut host = FakeHost::new();
    host.drop_write_reply = true;

    let error = install_entry(
        &mut host,
        "reviewed",
        &json!({"url": "https://example.test"}),
    )
    .expect_err("uncertain");

    assert_eq!(error.reason, UNCERTAIN);
    assert!(error.chain.is_none());
    assert_eq!(host.writes.len(), 1);
    assert!(host.servers().contains_key("reviewed"));
}

#[test]
fn a_write_reply_that_does_not_acknowledge_the_file_is_uncertain() {
    struct Reply(Value);
    impl ConfigHost for Reply {
        fn request(&mut self, method: &str, _params: &Value) -> Result<Map<String, Value>, Reason> {
            assert_eq!(method, "config/batchWrite");
            Ok(object(self.0.clone()))
        }
    }
    let receipt = Receipt {
        name: "reviewed".to_owned(),
        file_path: "/synthetic/config.toml".to_owned(),
        version: "1".to_owned(),
        entry_json: "{}".to_owned(),
        previous_version: None,
    };
    let replies = [
        json!({"status": "ok", "filePath": "/other.toml", "version": "2"}),
        json!({"status": "rejected", "filePath": "/synthetic/config.toml", "version": "2"}),
        json!({"status": "ok", "filePath": "/synthetic/config.toml", "version": ""}),
        json!({"status": "ok", "filePath": "/synthetic/config.toml", "version": 2}),
        json!({"status": "ok", "filePath": "/synthetic/config.toml", "version": "2",
               "overriddenMetadata": {"message": "overridden"}}),
    ];
    for reply in replies {
        let outcome = write(&mut Reply(reply.clone()), &receipt, None);

        assert_eq!(outcome, Err(UNCERTAIN), "{reply}");
    }
    let accepted = json!({"status": "ok", "filePath": "/synthetic/config.toml", "version": "2",
                          "overriddenMetadata": null});
    assert_eq!(
        write(&mut Reply(accepted), &receipt, None),
        Ok("2".to_owned())
    );
}

#[test]
fn a_read_only_layer_is_reported_as_read_only() {
    struct Readonly;
    impl ConfigHost for Readonly {
        fn request(
            &mut self,
            _method: &str,
            _params: &Value,
        ) -> Result<Map<String, Value>, Reason> {
            Err(READONLY)
        }
    }
    let receipt = Receipt {
        name: "reviewed".to_owned(),
        file_path: "/synthetic/config.toml".to_owned(),
        version: "1".to_owned(),
        entry_json: "{}".to_owned(),
        previous_version: None,
    };

    assert_eq!(write(&mut Readonly, &receipt, None), Err(READONLY));
}

#[test]
fn failed_verification_rolls_back_only_the_acknowledged_setup() {
    let mut host = FakeHost::new();
    let before = host.config.clone();
    host.corrupt_verification = true;

    let error = install_entry(
        &mut host,
        "reviewed",
        &json!({"url": "https://example.test"}),
    )
    .expect_err("rolled back");

    assert_eq!(error.reason, ROLLED_BACK);
    assert_eq!(host.config, before);
    assert!(host.writes.last().expect("write")["edits"][0]["value"].is_null());
    assert_eq!(
        error.chain,
        Some((
            host.path.clone(),
            vec![
                ("1".to_owned(), "2".to_owned()),
                ("2".to_owned(), "3".to_owned())
            ]
        ))
    );
}

#[test]
fn a_read_back_that_differs_from_what_was_written_rolls_back() {
    struct Drifting(FakeHost);
    impl ConfigHost for Drifting {
        fn request(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason> {
            let reply = self.0.request(method, params);
            if method == "config/read" && self.0.reads == 2 {
                self.0.config["mcp_servers"]["reviewed"] =
                    json!({"url": "https://example.test/other"});
                return Ok(object(self.0.payload_now()));
            }
            reply
        }
    }
    let mut host = Drifting(FakeHost::new());
    let entry = json!({"url": "https://example.test/reviewed"});

    let error =
        install(&mut host, "reviewed", &entry, &entry.to_string()).expect_err("rolled back");

    // The entry the read-back holds is not the one that was reviewed, so the
    // removal is refused as a change made by someone else.
    assert_eq!(error.reason, UNCERTAIN);
    assert!(error.chain.is_none());
}

#[test]
fn a_definition_in_another_layer_at_read_back_rolls_back_the_setup() {
    struct Shadowed(FakeHost);
    impl ConfigHost for Shadowed {
        fn request(&mut self, method: &str, params: &Value) -> Result<Map<String, Value>, Reason> {
            let reply = self.0.request(method, params);
            if method == "config/read" && self.0.reads == 2 {
                let mut payload = self.0.payload_now();
                let other = json!({
                    "name": {"type": "project", "file": self.0.path},
                    "version": "9",
                    "config": {"mcp_servers": {"reviewed": {}}},
                });
                payload["layers"]
                    .as_array_mut()
                    .expect("layers")
                    .push(other);
                return Ok(object(payload));
            }
            reply
        }
    }
    let mut host = Shadowed(FakeHost::new());
    let entry = json!({"url": "https://example.test/reviewed"});

    let error =
        install(&mut host, "reviewed", &entry, &entry.to_string()).expect_err("rolled back");

    assert_eq!(error.reason, ROLLED_BACK);
    assert!(!host.0.servers().contains_key("reviewed"));
}

#[test]
fn rollback_refuses_changed_host_configuration() {
    let mut host = FakeHost::new();
    let entry = json!({"url": "https://example.test"});
    let receipt = install_entry(&mut host, "reviewed", &entry).expect("installed");
    host.version += 1;
    host.config["user_edit"] = json!("preserved");

    assert_eq!(rollback(&mut host, &receipt, &entry), Err(CHANGED));

    assert_eq!(host.writes.len(), 1);
    assert_eq!(host.config["user_edit"], json!("preserved"));
    assert!(host.servers().contains_key("reviewed"));
}

#[test]
fn rollback_refuses_a_changed_entry_or_file() {
    let mut host = FakeHost::new();
    let entry = json!({"url": "https://example.test"});
    let receipt = install_entry(&mut host, "reviewed", &entry).expect("installed");

    assert_eq!(
        rollback(
            &mut host,
            &receipt,
            &json!({"url": "https://example.test/edited"})
        ),
        Err(CHANGED)
    );
    let elsewhere = Receipt {
        file_path: "/elsewhere/config.toml".to_owned(),
        ..receipt.clone()
    };
    assert_eq!(rollback(&mut host, &elsewhere, &entry), Err(CHANGED));
    assert_eq!(host.writes.len(), 1);
}

#[path = "codex_mcp_setup_op_tests.rs"]
mod op;
