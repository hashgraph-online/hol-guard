use std::path::{Path, PathBuf};

use guard_policy_snapshot::canonical_json_bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::evaluate;

const KEY: [u8; 32] = [7; 32];

fn digest(c: char) -> String {
    c.to_string().repeat(64)
}

struct Cache {
    _guard: tempfile::TempDir,
    root: PathBuf,
}

impl Cache {
    fn new() -> Self {
        let guard = tempfile::tempdir().unwrap();
        // The reader refuses symlinked path components, and some platforms
        // place temporary directories behind one.
        let root = guard.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("objects")).unwrap();
        Self {
            _guard: guard,
            root,
        }
    }

    fn path(&self, reference: &Value) -> PathBuf {
        let sha = reference["sha256"].as_str().unwrap();
        self.root.join("objects").join(format!("{sha}.json"))
    }

    fn put(&self, bytes: &[u8]) -> Value {
        let sha = hex::encode(Sha256::digest(bytes));
        let reference = json!({
            "sha256": sha, "length": bytes.len(), "expanded_length": bytes.len(), "kind": "data",
        });
        std::fs::write(self.path(&reference), bytes).unwrap();
        reference
    }

    fn json(&self, value: &Value) -> Value {
        self.put(&canonical_json_bytes(value).unwrap())
    }

    fn located(&self, value: &Value) -> Value {
        let mut reference = self.json(value);
        let sha = reference["sha256"].as_str().unwrap().to_owned();
        reference["location"] = json!({
            "tag": format!("extension-data-{}-1.2-000001", "5".repeat(40)),
            "asset": format!("object-{sha}.json"),
        });
        reference
    }

    /// Store `bytes` as a concatenation of two halves under `schema`.
    fn concat(&self, bytes: &[u8], schema: &str) -> Value {
        let middle = bytes.len() / 2;
        let parts = [self.put(&bytes[..middle]), self.put(&bytes[middle..])];
        let mut reference = self.json(&json!({"schema": schema, "parts": parts}));
        reference["kind"] = json!("concat");
        reference["expanded_length"] = json!(bytes.len());
        reference
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

fn page(schema: &str, field: &str, items: Value) -> Value {
    json!({"schema": schema, field: items, "next": null})
}

fn publication() -> Value {
    json!({
        "schema": "guard.command-pack-bundle.v1", "source_sha": "5".repeat(40),
        "engine": digest('4'), "publication_id": "0.0", "authority_epoch": 1,
        "issued_at": null, "expires_at": null, "policy": {"revocations": {"epoch": 0}},
    })
}

/// A sealed installed activation over `selected` and the registry `ids`.
fn activation(cache: &Cache, selected: &[&str], ids: &[&str], distribution: Value) -> Value {
    let catalogs: Vec<Value> = ids
        .iter()
        .map(|id| cache.located(&json!([{"extension_id": id}])))
        .collect();
    let header = json!({
        "schema": "guard.command-pack-activation.v2", "revision": 1, "previous_digest": null,
        "program_digest": digest('1'), "catalog_digest": digest('2'), "trust_digest": digest('3'),
        "engine": digest('4'), "source_sha": "5".repeat(40), "publication_id": "0.0",
        "root_digest": distribution["sha256"], "authority_epoch": 1, "revocation_epoch": 0,
        "issued_at": null, "expires_at": null,
        "selection": cache.json(&page("guard.command-pack-selection-page.v1", "ids", json!(selected))),
        "selected_count": selected.len(),
        "registry": cache.json(&page("guard.command-pack-registry-page.v1", "items", json!(catalogs))),
        "registry_count": ids.len(),
        "executables": cache.json(&page("guard.command-pack-executables-page.v1", "items", json!(["/bin/a"]))),
        "executable_count": 1, "distribution": distribution, "authority_profile": "installed",
    });
    evaluate(
        &json!({"operation": "seal", "purpose": "activation", "payload": header}),
        &KEY,
    )
    .unwrap()
}

/// A refused record answers on stdout; it reads here as the reason it names.
fn open(cache: &Cache, sealed: &Value, key: &[u8]) -> Result<Value, String> {
    let answer = evaluate(
        &json!({
            "operation": "open", "purpose": "activation", "directory": cache.root(),
            "record": sealed["record"], "digest": sealed["digest"], "mac": sealed["mac"],
        }),
        key,
    )?;
    match answer["fault"].as_str() {
        Some("refused") => Err(answer["reason"].as_str().unwrap_or_default().to_owned()),
        _ => Ok(answer),
    }
}

fn header(sealed: &Value) -> Value {
    serde_json::from_str(sealed["record"].as_str().unwrap()).unwrap()
}

#[test]
fn an_activation_opens_with_the_inventories_it_binds() {
    let cache = Cache::new();
    let distribution = cache.json(&publication());
    let sealed = activation(
        &cache,
        &["command.a"],
        &["command.a", "command.b"],
        distribution,
    );
    let opened = open(&cache, &sealed, &KEY).unwrap();
    assert_eq!(opened["selected"], json!(["command.a"]));
    assert_eq!(opened["registry_ids"], json!(["command.a", "command.b"]));
    assert_eq!(opened["executables"], json!(["/bin/a"]));
    assert_eq!(opened["registry"].as_array().unwrap().len(), 2);
    assert_eq!(opened["value"]["revision"], json!(1));
}

#[test]
fn concatenated_objects_expand_under_their_own_schema() {
    let cache = Cache::new();
    let bytes = canonical_json_bytes(&publication()).unwrap();
    let distribution = cache.concat(&bytes, "guard.pack-concat.v1");
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    assert!(open(&cache, &sealed, &KEY).is_ok());
    let cache = Cache::new();
    let distribution = cache.concat(&bytes, "guard.delivery-concat.v2");
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation metadata object invalid".into())
    );
}

#[test]
fn a_publication_keeps_its_signed_bytes_but_not_a_duplicated_field() {
    let cache = Cache::new();
    let pretty = serde_json::to_vec_pretty(&publication()).unwrap();
    let distribution = cache.put(&pretty);
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    assert!(open(&cache, &sealed, &KEY).is_ok());

    let cache = Cache::new();
    let canonical = canonical_json_bytes(&publication()).unwrap();
    let mut duplicated = br#"{"schema":"guard.command-pack-bundle.v1","#.to_vec();
    duplicated.extend_from_slice(&canonical[1..]);
    let distribution = cache.put(&duplicated);
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation metadata object invalid".into())
    );
}

#[test]
fn a_wrong_key_is_tampered_before_any_object_is_read() {
    let cache = Cache::new();
    let distribution = cache.json(&publication());
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    std::fs::remove_dir_all(cache.root().join("objects")).unwrap();
    let opened = open(&cache, &sealed, &[9; 32]).unwrap();
    assert_eq!(opened["fault"], json!("tampered"));
}

#[test]
fn missing_corrupt_or_inconsistent_metadata_refuses_the_record() {
    let cache = Cache::new();
    let distribution = cache.json(&publication());
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    let registry = header(&sealed)["registry"].clone();
    std::fs::write(cache.path(&registry), b"{}").unwrap();
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation metadata object integrity invalid".into())
    );
    std::fs::remove_file(cache.path(&registry)).unwrap();
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation metadata object unavailable".into())
    );

    let cache = Cache::new();
    let distribution = cache.json(&publication());
    let sealed = activation(&cache, &["command.c"], &["command.a"], distribution);
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation registry inventory invalid".into())
    );

    let cache = Cache::new();
    let distribution = cache.json(&publication());
    let sealed = activation(
        &cache,
        &["command.b", "command.a"],
        &["command.a", "command.b"],
        distribution,
    );
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation selected inventory invalid".into())
    );

    let cache = Cache::new();
    let mut other = publication();
    other["engine"] = json!(digest('9'));
    let distribution = cache.json(&other);
    let sealed = activation(&cache, &["command.a"], &["command.a"], distribution);
    assert_eq!(
        open(&cache, &sealed, &KEY),
        Err("activation publication identity invalid".into())
    );
}

#[test]
fn page_chains_must_hold_exactly_the_counted_entries() {
    for (count, reason) in [
        (3, "activation metadata is incomplete"),
        (1, "activation metadata has surplus entries"),
    ] {
        let cache = Cache::new();
        let distribution = cache.json(&publication());
        let catalogs: Vec<Value> = ["command.a", "command.b"]
            .iter()
            .map(|id| cache.located(&json!([{"extension_id": id}])))
            .collect();
        let mut value = header(&activation(
            &cache,
            &["command.a"],
            &["command.a"],
            distribution,
        ));
        let map = value.as_object_mut().unwrap();
        map.remove("authority_schema_version");
        map.remove("purpose");
        map["registry"] = cache.json(&page(
            "guard.command-pack-registry-page.v1",
            "items",
            json!(catalogs),
        ));
        map["registry_count"] = json!(count);
        let sealed = evaluate(
            &json!({"operation": "seal", "purpose": "activation", "payload": value}),
            &KEY,
        )
        .unwrap();
        assert_eq!(open(&cache, &sealed, &KEY), Err(reason.into()));
    }
}
