//! `script_operand` against vectors recorded from the retired Python
//! `_script_operand`. The fixture is data only; nothing here recomputes the
//! Python result.

use crate::shell_secret_read_support::script_operand;
use serde_json::Value;

#[test]
fn script_operand_matches_recorded_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../tests/fixtures/script_operand_vectors.json"
    ))
    .expect("vectors parse");
    assert!(vectors.len() > 1000, "vector set shrank: {}", vectors.len());
    for vector in &vectors {
        let executable = vector["executable"].as_str().expect("executable");
        let args: Vec<String> = vector["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|arg| arg.as_str().expect("arg").to_owned())
            .collect();
        let expected = vector["expected"].as_array().map(|pair| {
            (
                pair[0].as_str().expect("operand").to_owned(),
                pair[1].as_bool().expect("is_shell"),
            )
        });
        assert_eq!(
            script_operand(executable, &args),
            expected,
            "{executable} {args:?}"
        );
    }
}

#[test]
fn double_dash_and_bun_keep_their_script_operand() {
    let args = |items: &[&str]| -> Vec<String> { items.iter().map(|s| (*s).to_owned()).collect() };
    assert_eq!(
        script_operand("python", &args(&["--", "script.py"])),
        Some(("script.py".to_owned(), false))
    );
    assert_eq!(
        script_operand("bun", &args(&["script.ts"])),
        Some(("script.ts".to_owned(), false))
    );
}
