use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::io::Cursor;

fn object(bytes: &[u8], kind: &str, expanded: usize) -> Value {
    let digest = hex::encode(Sha256::digest(bytes));
    json!({"sha256":digest,"length":bytes.len(),"expanded_length":expanded,"kind":kind,
        "location":{"tag":format!("extension-data-{}-0.0-000000","a".repeat(40)),"asset":format!("object-{digest}.json")}})
}
fn data(value: &Value) -> (Value, Vec<u8>) {
    let bytes = serde_json::to_vec(value).unwrap();
    (object(&bytes, "data", bytes.len()), bytes)
}
fn payload(id: &str) -> Value {
    json!({"id":id,"schemaVersion":"guard.extension-contribution.v2"})
}
fn leaf(rows: Vec<Value>, prefix: &str) -> (Value, Vec<u8>) {
    data(&json!({"schema":"guard.pack-index.v1","kind":"leaf","prefix":prefix,"entries":rows}))
}
fn run(
    index: Value,
    count: usize,
    responses: Vec<Vec<u8>>,
    limit: usize,
) -> (Result<Value>, Vec<Value>) {
    let mut root = crate::bundle_metadata::tests::fixture();
    root["policy"]["root"]["extensions"] = json!(count.max(1));
    root["compatibility"] =
        json!({"commands":{"count":count,"index":index},"mcp":{"count":0,"index":null}});
    let input = json!({"family":"commands","source_sha":"a".repeat(40),"engine":"b".repeat(64),
        "data":serde_json::to_string(&root).unwrap(),"max_bytes":limit});
    let mut encoded = Vec::new();
    for bytes in responses {
        encoded.extend(serde_json::to_vec(&json!({"data":STANDARD.encode(bytes)})).unwrap());
        encoded.push(b'\n');
    }
    let mut output = Vec::new();
    let mut io =
        MetadataExchange::installed(Cursor::new(encoded), &mut output, "a".repeat(40), limit);
    let result = read(&mut io, &input);
    drop(io);
    let records = output
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| strict_json::decode(line).unwrap())
        .filter(|value| value["kind"] == "compatibility-record")
        .map(|value| value["payload"].clone())
        .collect();
    (result, records)
}

#[test]
fn traverses_hash_branches_and_emits_global_identity_order() {
    let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut payloads = Vec::new();
    for n in 0..65 {
        let id = format!("command.example{n:03}");
        let (reference, bytes) = data(&payload(&id));
        let prefix = hex::encode(Sha256::digest(id.as_bytes()))[..1].to_owned();
        groups
            .entry(prefix)
            .or_default()
            .push(json!([id, reference]));
        payloads.push(bytes);
    }
    let mut children = Vec::new();
    let mut pages = Vec::new();
    for (prefix, rows) in groups {
        let count = rows.len();
        let (reference, bytes) = leaf(rows, &prefix);
        children.push(json!([prefix, count, reference]));
        pages.push(bytes);
    }
    let (index, root) = data(
        &json!({"schema":"guard.pack-index.v1","kind":"branch","prefix":"","children":children}),
    );
    let responses = std::iter::once(root)
        .chain(pages.into_iter().rev())
        .chain(payloads)
        .collect();
    let (result, records) = run(index, 65, responses, MAX_BYTES);
    assert!(result.unwrap()["available"].as_bool().unwrap());
    assert_eq!(records.len(), 65);
    assert_eq!(records.first().unwrap()["id"], "command.example000");
    assert_eq!(records.last().unwrap()["id"], "command.example064");
}

#[test]
fn rejects_identity_schema_duplicate_json_and_corrupt_bytes_without_partial_admission() {
    for bytes in [
        serde_json::to_vec(&payload("command.substituted")).unwrap(),
        serde_json::to_vec(&json!({"id":"command.example","schemaVersion":"guard.mcp-server-contribution.v1"})).unwrap(),
        br#"{"id":"command.example","id":"command.substituted","schemaVersion":"guard.extension-contribution.v2"}"#.to_vec(),
    ] {
        let reference = object(&bytes, "data", bytes.len());
        let (index, page) = leaf(vec![json!(["command.example",reference])], "");
        let (result, records) = run(index, 1, vec![page,bytes], MAX_BYTES);
        assert!(result.is_err());
        assert!(records.is_empty());
    }
    let (reference, _) = data(&payload("command.example"));
    let (index, page) = leaf(vec![json!(["command.example", reference])], "");
    assert!(run(index, 1, vec![page, b"corrupt".to_vec()], MAX_BYTES)
        .0
        .is_err());
}

#[test]
fn enforces_index_counts_and_both_transfer_and_expansion_budgets() {
    let mut value = payload("command.example");
    value["description"] = json!("x".repeat(5000));
    let (reference, bytes) = data(&value);
    let (index, page) = leaf(vec![json!(["command.example", reference])], "");
    let (result, _) = run(index.clone(), 1, vec![page.clone()], 1);
    assert!(result.unwrap_err().contains("byte budget"));
    let (result, _) = run(index.clone(), 1, vec![page.clone()], 4096);
    assert!(result.unwrap_err().contains("expanded byte budget"));
    assert!(run(index, 2, vec![page, bytes], MAX_BYTES)
        .0
        .unwrap_err()
        .contains("count"));
}

#[test]
fn admits_bounded_concatenated_metadata_and_rejects_cross_source_children() {
    let mut value = payload("command.example");
    value["description"] = json!("x".repeat(70_000));
    value["settings"] = json!({"minimum":0.5,"marker":{"$serde_json::private::Number":"1"}});
    let bytes = serde_json::to_vec(&value).unwrap();
    let parts: Vec<_> = bytes
        .chunks(65536)
        .map(|chunk| object(chunk, "data", chunk.len()))
        .collect();
    let concat =
        serde_json::to_vec(&json!({"schema":"guard.delivery-concat.v2","parts":parts})).unwrap();
    let reference = object(&concat, "concat", bytes.len());
    let (index, page) = leaf(vec![json!(["command.example", reference])], "");
    let responses = std::iter::once(page)
        .chain(std::iter::once(concat))
        .chain(bytes.chunks(65536).map(|s| s.to_vec()))
        .collect();
    assert!(run(index, 1, responses, MAX_BYTES).1 == vec![value]);
    let (mut reference, bytes) = data(&payload("command.example"));
    reference["location"]["tag"] = json!(format!("extension-data-{}-0.0-000000", "d".repeat(40)));
    let (index, page) = leaf(vec![json!(["command.example", reference])], "");
    assert!(run(index, 1, vec![page, bytes], MAX_BYTES)
        .0
        .unwrap_err()
        .contains("source"));
}

#[test]
fn only_genuine_legacy_absence_skips_the_installed_bundle() {
    let runtime = json!({"schema":"hol-guard-native-runtime.v1"});
    let compiler = json!({"schema":"hol-guard-native-source-compiler.v2"});
    // Drive the dispatcher so the request carries its operation key, as
    // the Python caller sends it.
    let ask = |request: Value| {
        let mut request = request;
        request["operation"] = json!("installed-presence");
        super::super::evaluate(&serde_json::to_vec(&request).unwrap())
    };
    let advertised = |bundle: bool, manifests: Value| {
        ask(json!({"bundle":bundle,"manifests":manifests})).unwrap()["advertised"]
            .as_bool()
            .unwrap()
    };
    assert!(!advertised(false, json!([null, null])));
    assert!(!advertised(false, json!([runtime, compiler])));
    assert!(advertised(true, json!([null, null])));
    assert!(advertised(true, json!([runtime, compiler])));
    let mut bound = runtime.clone();
    bound["command_pack_bundle"] = json!({});
    assert!(advertised(false, json!([bound, compiler])));
    // One missing, swapped or unknown manifest cannot prove legacy absence.
    assert!(advertised(false, json!([runtime, null])));
    assert!(advertised(false, json!([compiler, runtime])));
    assert!(advertised(false, json!(["corrupt", compiler])));
    for malformed in [
        json!({"bundle":false}),
        json!({"bundle":"no","manifests":[null,null]}),
        json!({"bundle":false,"manifests":[null]}),
        json!({"bundle":false,"manifests":[null,null],"extra":1}),
    ] {
        assert!(ask(malformed).is_err());
    }
}
