use super::*;
use guard_command::native_command_program::digest_value;
use serde_json::json;
use sha2::{Digest, Sha256};

const KEY: [u8; 32] = [7; 32];
const PACK: &str = "command.synthetic";

fn bytes(value: &Value) -> Vec<u8> {
    let mut value = value.clone();
    value.sort_all_objects();
    serde_json::to_vec(&value).unwrap()
}

fn put(directory: &Path, value: &Value) -> Value {
    let data = bytes(value);
    let digest = hex::encode(Sha256::digest(&data));
    std::fs::write(
        directory.join("objects").join(format!("{digest}.json")),
        &data,
    )
    .unwrap();
    json!({"sha256":digest,"length":data.len(),"expanded_length":data.len(),"kind":"data"})
}

struct Fixture {
    directory: tempfile::TempDir,
    header: Value,
    set: Value,
    manifest: Value,
    program: Value,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        std::fs::create_dir(directory.path().join("objects")).unwrap();
        std::fs::create_dir(directory.path().join("sets")).unwrap();
        let catalog = put(directory.path(), &json!([{"extension_id":PACK}]));
        let program = json!({"program_digest":"1".repeat(64),"catalog_digest":catalog["sha256"],
            "trust_digest":"3".repeat(64),"nodes":{}});
        // Deliberately not this runtime's engine: migration must not try to
        // execute or admit the predecessor's compiled IR in the new engine.
        let engine = "4".repeat(64);
        let manifest = json!({"schema":"guard.command-policy-pack.v1","extension_id":PACK,
            "engine":engine,"semantic_profile":"cpython-3.12-ucd15",
            "program_digest":program["program_digest"],"trust_digest":program["trust_digest"],
            "program":put(directory.path(), &program),"catalog":catalog});
        let index = put(
            directory.path(),
            &json!({"schema":"guard.pack-index.v1","kind":"leaf",
            "prefix":"","entries":[[PACK,put(directory.path(), &manifest)]]}),
        );
        let root = json!({"schema":"guard.command-pack-release.v1","engine":engine,
            "extensions":1,"index":index});
        let identities = json!([{"extension":PACK,"program":program["program_digest"],
            "catalog":program["catalog_digest"],"trust":program["trust_digest"]}]);
        let program_digest = digest_value(
            b"hol-guard.active-command-program.v1\0",
            &json!({"engine":engine,"packs":identities}),
        )
        .unwrap();
        let catalog_digest =
            digest_value(b"hol-guard.active-command-catalog.v1\0", &identities).unwrap();
        let trust_digest =
            digest_value(b"hol-guard.active-command-trust.v1\0", &identities).unwrap();
        let selection = put(
            directory.path(),
            &json!({"schema":"guard.command-pack-selection-page.v1",
            "ids":[PACK],"next":null}),
        );
        let distribution = put(
            directory.path(),
            &json!({"schema":"guard.command-pack-bundle.v1",
            "source_sha":"5".repeat(40),"engine":engine,"publication_id":"0.0","authority_epoch":1,
            "issued_at":null,"expires_at":null,"policy":{"root":root,"revocations":{"epoch":0}}}),
        );
        let mut located_catalog = catalog.clone();
        located_catalog["location"] = json!({"tag":format!("extension-data-{}-1.2-000001","5".repeat(40)),
            "asset":format!("object-{}.json",catalog["sha256"].as_str().unwrap())});
        let header = json!({"schema":"guard.command-pack-activation.v2","revision":2,
            "previous_digest":"6".repeat(64),"program_digest":program_digest,
            "catalog_digest":catalog_digest,"trust_digest":trust_digest,"engine":engine,
            "source_sha":"5".repeat(40),"publication_id":"0.0","root_digest":distribution["sha256"],
            "authority_epoch":1,"revocation_epoch":0,"issued_at":null,"expires_at":null,
            "selection":selection,"selected_count":1,
            "registry":put(directory.path(), &json!({"schema":"guard.command-pack-registry-page.v1",
                "items":[located_catalog],"next":null})),"registry_count":1,
            "executables":null,"executable_count":0,"distribution":distribution,
            "authority_profile":"installed"});
        let set = json!({"schema":"guard.command-pack-cache.v1","release":put(directory.path(), &root),
            "selection":selection,"selected_count":1});
        let fixture = Self {
            directory,
            header,
            set,
            manifest,
            program,
        };
        fixture.write_set();
        fixture
    }

    fn write_set(&self) {
        std::fs::write(
            self.directory.path().join("sets").join(format!(
                "{}.json",
                self.header["program_digest"].as_str().unwrap()
            )),
            bytes(&self.set),
        )
        .unwrap();
    }

    fn opened(&self) -> Res<Value> {
        let sealed = crate::pack_lifecycle::evaluate(&json!({"kind":"record","operation":"seal",
            "purpose":"activation","key":hex::encode(KEY),"payload":self.header}))
        .unwrap();
        super::super::open(&sealed, &KEY, self.directory.path())
    }

    fn rewrite_manifest(&mut self) {
        self.manifest["program"] = put(self.directory.path(), &self.program);
        let path = self.directory.path().join("objects").join(format!(
            "{}.json",
            self.header["distribution"]["sha256"].as_str().unwrap()
        ));
        let mut publication: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let root = &mut publication["policy"]["root"];
        root["index"] = put(
            self.directory.path(),
            &json!({"schema":"guard.pack-index.v1","kind":"leaf",
            "prefix":"","entries":[[PACK,put(self.directory.path(), &self.manifest)]]}),
        );
        self.set["release"] = put(self.directory.path(), root);
        self.header["distribution"] = put(self.directory.path(), &publication);
        self.header["root_digest"] = self.header["distribution"]["sha256"].clone();
        self.write_set();
    }

    fn check(&self, binding: Option<Value>, catalog: Option<&str>) -> Res<()> {
        self.check_with_limits(binding, catalog, PackAdmissionBudget::resident())
    }

    fn check_with_limits(
        &self,
        binding: Option<Value>,
        catalog: Option<&str>,
        limits: PackAdmissionBudget,
    ) -> Res<()> {
        use super::super::super::records::{authenticated_record, verify_record, SNAPSHOT_PURPOSE};
        let mut snapshot = json!({"revision":1840,"catalog_digest":self.header["catalog_digest"],
            "layers_json":"[]","previous_digest":"7".repeat(64),"committed_at":"2026-10-22T00:00:00Z"})
            .as_object().unwrap().clone();
        if let Some(value) = binding {
            snapshot.insert("command_pack_record_digest".into(), value);
        }
        let (record, digest, mac) =
            authenticated_record(&snapshot, &KEY, SNAPSHOT_PURPOSE).unwrap();
        let snapshot = verify_record(&record, &digest, &mac, &KEY, SNAPSHOT_PURPOSE).unwrap();
        validate_predecessor_with_limits(
            &snapshot,
            &json!("8".repeat(64)),
            &self.opened()?,
            catalog.unwrap_or(self.header["catalog_digest"].as_str().unwrap()),
            self.directory.path(),
            limits,
        )
    }
}

#[test]
fn authenticated_legacy_snapshot_accepts_only_its_old_engine_pack_metadata() {
    let fixture = Fixture::new();
    assert_ne!(
        fixture.header["engine"],
        guard_command::source_cli::compiler_info()["implementation_digest"]
    );
    fixture.check(None, None).unwrap();
}

#[test]
fn present_binding_never_uses_legacy_recovery() {
    let fixture = Fixture::new();
    fixture.check(Some(json!("8".repeat(64))), None).unwrap();
    for value in [Value::Null, json!(false), json!(7), json!("9".repeat(64))] {
        assert!(fixture.check(Some(value.clone()), None).is_err(), "{value}");
    }
}

#[test]
fn legacy_recovery_refuses_a_different_signed_catalog_or_cache_selection() {
    let fixture = Fixture::new();
    assert!(fixture.check(None, Some(&"9".repeat(64))).is_err());
    for (field, value) in [
        ("schema", json!("other")),
        ("selected_count", json!(2)),
        ("selection", Value::Null),
        ("release", Value::Null),
    ] {
        let mut fixture = Fixture::new();
        fixture.set[field] = value;
        fixture.write_set();
        assert!(fixture.check(None, None).is_err(), "{field}");
    }
}

#[test]
fn legacy_recovery_refuses_changed_aggregate_identities_or_cache_bytes() {
    for field in ["program_digest", "catalog_digest", "trust_digest", "engine"] {
        let mut fixture = Fixture::new();
        fixture.header[field] = json!("9".repeat(64));
        fixture.write_set();
        assert!(fixture.check(None, None).is_err(), "{field}");
    }
    let fixture = Fixture::new();
    let reference = fixture.manifest["program"]["sha256"].as_str().unwrap();
    // A syntactically valid replacement still fails the content-address check.
    std::fs::write(
        fixture
            .directory
            .path()
            .join("objects")
            .join(format!("{reference}.json")),
        b"{}",
    )
    .unwrap();
    assert!(fixture.check(None, None).is_err());
}

#[test]
fn legacy_recovery_refuses_authenticated_leaf_metadata_mismatches() {
    for field in ["extension_id", "engine", "program_digest", "trust_digest"] {
        let mut fixture = Fixture::new();
        fixture.manifest[field] = json!(if field == "extension_id" {
            "command.other".to_owned()
        } else {
            "9".repeat(64)
        });
        fixture.rewrite_manifest();
        assert!(fixture.check(None, None).is_err(), "{field}");
    }
    for field in ["catalog_digest", "trust_digest"] {
        let mut fixture = Fixture::new();
        fixture.program[field] = json!("9".repeat(64));
        if field == "trust_digest" {
            fixture.manifest[field] = fixture.program[field].clone();
        }
        fixture.rewrite_manifest();
        assert!(fixture.check(None, None).is_err(), "program {field}");
    }
    let fixture = Fixture::new();
    let reference = fixture.manifest["program"]["sha256"].as_str().unwrap();
    std::fs::remove_file(
        fixture
            .directory
            .path()
            .join("objects")
            .join(format!("{reference}.json")),
    )
    .unwrap();
    assert!(fixture.check(None, None).is_err());
}

#[test]
fn legacy_recovery_uses_the_catalogs_canonical_identity() {
    let mut fixture = Fixture::new();
    let value = json!([{"extension_id":PACK}]);
    let data = serde_json::to_vec_pretty(&value).unwrap();
    let digest = hex::encode(Sha256::digest(&data));
    std::fs::write(
        fixture
            .directory
            .path()
            .join("objects")
            .join(format!("{digest}.json")),
        &data,
    )
    .unwrap();
    fixture.manifest["catalog"] = json!({"sha256":digest,"length":data.len(),
        "expanded_length":data.len(),"kind":"data"});
    fixture.rewrite_manifest();
    fixture.check(None, None).unwrap();
}

#[test]
fn metadata_overhead_uses_individual_blob_bounds_not_the_program_budget() {
    let fixture = Fixture::new();
    let first = put(fixture.directory.path(), &json!("a".repeat(64)));
    let second = put(fixture.directory.path(), &json!("b".repeat(64)));
    let oversized = put(fixture.directory.path(), &json!("c".repeat(96)));
    let mut reader = Metadata {
        directory: fixture.directory.path(),
        blob_limit: 96,
    };
    assert!(
        first["expanded_length"].as_u64().unwrap() + second["expanded_length"].as_u64().unwrap()
            > 96
    );
    assert_eq!(reader.json(&first).unwrap(), json!("a".repeat(64)));
    assert_eq!(reader.json(&second).unwrap(), json!("b".repeat(64)));
    assert!(reader.json(&oversized).is_err());
}

#[test]
fn legacy_program_budget_excludes_metadata_overhead_but_still_caps_programs() {
    let fixture = Fixture::new();
    let program_bytes = guard_policy_snapshot::canonical_json_bytes(&fixture.program)
        .unwrap()
        .len();
    let limits = PackAdmissionBudget {
        program_bytes,
        ..PackAdmissionBudget::resident()
    };
    fixture.check_with_limits(None, None, limits).unwrap();
    assert!(fixture
        .check_with_limits(
            None,
            None,
            PackAdmissionBudget {
                program_bytes: program_bytes - 1,
                ..limits
            }
        )
        .is_err());
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/catalog-delivery/packs.v1.json"
    ))
    .unwrap();
    assert_eq!(contract["max_blob_bytes"], json!(8 * 1024 * 1024));
    assert_eq!(contract["max_object_bytes"], json!(65536));
}
