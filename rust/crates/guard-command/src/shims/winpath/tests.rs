use super::{nt_join, nt_normpath, nt_split, WinPath};

#[test]
fn matches_cpython_pure_windows_path() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/winpath_oracle.v1.json"
    ))
    .expect("oracle json");
    assert_eq!(document["schema"], "guard-winpath-oracle.v1");
    let mut failures: Vec<String> = Vec::new();
    for case in document["cases"].as_array().expect("cases") {
        let kind = case[0].as_str().expect("kind");
        let input = case[1].as_str().expect("input");
        let expected = case[2].as_str().expect("expected");
        let actual = match kind {
            "str" => WinPath::new(input).to_string(),
            "name" => WinPath::new(input).name(),
            "parent" => WinPath::new(input).parent().to_string(),
            "abs" => if WinPath::new(input).is_absolute() {
                "1"
            } else {
                "0"
            }
            .to_owned(),
            "normpath" => nt_normpath(input),
            "join" => {
                let (base, child) = input.split_once('\0').unwrap_or((input, ""));
                WinPath::new(base).join(child).to_string()
            }
            "split" => {
                let (head, tail) = nt_split(input);
                format!("{head}\0{tail}")
            }
            "ntjoin" => {
                let (base, child) = input.split_once('\0').unwrap_or((input, ""));
                nt_join(base, child)
            }
            other => panic!("unknown oracle kind {other}"),
        };
        if actual != expected {
            failures.push(format!(
                "{kind}({input:?}): got {actual:?}, want {expected:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
