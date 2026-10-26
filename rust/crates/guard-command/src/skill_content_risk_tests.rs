use super::*;
use serde_json::Value;

const VECTORS: &str = include_str!("../tests/fixtures/skill_content_risk_vectors.json");

fn detail_names(detail: &str) -> Vec<String> {
    let rest = detail.trim_start_matches("Unicode controls found: ");
    let mut names: Vec<String> = rest.split(", ").map(str::to_string).collect();
    names.sort();
    names
}

#[test]
fn skill_content_risk_matches_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("fixture json");
    assert!(vectors.len() >= 150);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let content = vector["content"].as_str().unwrap();
        assert_eq!(
            Value::Bool(NativeSkillProtection.has_skill_structure(content)),
            vector["has_skill_structure"],
            "has_skill_structure {name}"
        );
        let mut got: Vec<Value> = NativeSkillProtection
            .detect_skill_content_risk(content)
            .iter()
            .map(RiskSignalV2::to_value)
            .collect();
        let mut want = vector["signals"].as_array().unwrap().clone();
        if vector.get("unordered_unicode_names").is_some() {
            for list in [&mut got, &mut want] {
                for sig in list.iter_mut() {
                    if sig["signal_id"] == "skill.unicode-controls" {
                        let names = detail_names(sig["technical_detail"].as_str().unwrap());
                        sig["technical_detail"] = Value::from(names);
                    }
                }
            }
        }
        assert_eq!(got, want, "signals {name}");
    }
}

#[test]
fn base64_strictness() {
    assert!(b64decode_py("QUJD").is_some());
    assert!(b64decode_py("QUJDR").is_none());
    assert_eq!(b64decode_py("QQ=="), Some(b"A".to_vec()));
    assert_eq!(b64decode_py("QUI"), Some(b"AB".to_vec()));
}
