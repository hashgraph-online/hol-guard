//! A word spelled with ANSI-C escapes answers as the word it spells.
use super::tests::{controls, decision, github};

/// `grep -n $'\t' file` is what an agent writes whenever a tab is the
/// separator. The word runs nothing, so the command models exactly and needs
/// no approval, the same as the text it spells.
#[test]
fn an_ansi_c_operand_models_exactly() {
    let controls = controls(github("enabled", None), false);
    for (written, spelled) in [
        ("grep -n $'\\t' src/main.rs", "grep -n '\t' src/main.rs"),
        ("printf '%s' $'hello'", "printf '%s' hello"),
    ] {
        assert_eq!(decision(&controls, written).0, "allow", "{written}");
        assert_eq!(
            decision(&controls, written),
            decision(&controls, spelled),
            "{written}"
        );
    }
}

/// Reading the escapes must not become a way to write a program name past its
/// owner: `$'\x64ocker'` is docker, and it is answered for as docker.
#[test]
fn an_ansi_c_program_name_answers_as_the_program_it_spells() {
    let mut layer = github("enabled", None);
    layer.as_array_mut().unwrap().push(serde_json::json!({
        "target_kind": "extension", "target_id": "command.container-runtime", "state": "disabled"
    }));
    let controls = controls(layer, false);
    assert_eq!(decision(&controls, "docker ps").0, "block");
    assert_eq!(
        decision(&controls, "$'\\x64ocker' ps"),
        decision(&controls, "docker ps")
    );
}
