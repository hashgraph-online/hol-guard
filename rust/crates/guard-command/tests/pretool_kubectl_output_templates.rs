use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn decide(command: &str, home: &std::path::Path) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        None,
        None,
        home.to_str(),
        home.to_str(),
    );
    // The reason code says which rule answered, so a surprising decision
    // names it instead of leaving the reader to guess.
    (result.decision, result.reason_code)
}

/// A JSONPath that selects a container's environment names spells `.env`, and
/// the credential-location screen reads the command as text, so the narrower
/// read went to review while `-o yaml` -- which prints the same list and its
/// values -- was allowed.
#[test]
fn an_output_template_selecting_environment_names_is_not_a_dotenv_read() {
    let root = std::env::temp_dir().join(format!("guard-kubectl-templates-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    for (command, expected) in [
        // The wider read this proof already admitted.
        ("kubectl -n web get deploy api -o yaml", "allow"),
        // The narrower reads that the screen refused.
        (
            "kubectl -n web get deploy api -o jsonpath='{.spec.template.spec.containers[0].env[*].name}'",
            "allow",
        ),
        (
            "kubectl -n web get deploy api -o 'jsonpath={range .spec.template.spec.containers[0].env[*]}{.name}{\"\\n\"}{end}'",
            "allow",
        ),
        (
            "kubectl -n web get deploy api -o=jsonpath='{.spec.template.spec.containers[0].env[*].name}'",
            "allow",
        ),
        (
            "kubectl -n web get deploy api --output=jsonpath='{.spec.template.spec.containers[0].env[*].name}'",
            "allow",
        ),
        (
            "kubectl -n web get deploy api -o go-template='{{range .spec.template.spec.containers}}{{range .env}}{{.name}}{{end}}{{end}}'",
            "allow",
        ),
        (
            "kubectl -n web get deploy api -o custom-columns=NAME:.spec.template.spec.containers[0].env[0].name",
            "allow",
        ),
        (
            "kubectl -n web get deploy api -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' 2>/dev/null",
            "allow",
        ),
        // A Secret is refused by the read proof itself, under every spelling.
        (
            "kubectl -n web get secret api -o jsonpath='{.data.token}'",
            "review",
        ),
        // A selector asking for a credential says what the command is for, so
        // the whole segment keeps its signal.
        (
            "kubectl -n web get deploy api -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name==\"PASSWORD\")].value}'",
            "review",
        ),
        // A template is set aside only where it cannot spell a path, and only
        // the template itself is: an operand naming a credential file keeps
        // its own screen.
        (
            "kubectl -n web get deploy api -o jsonpath='{.spec.template.spec.volumes[*].hostPath.path}' ~/.ssh/id_rsa",
            "review",
        ),
        // Neither a format this grammar does not know nor an empty template
        // sheds anything.
        (
            "kubectl -n web get deploy api -o custom-columns-file=./columns.txt",
            "review",
        ),
    ] {
        let (decision, reason_code) = decide(command, &root);
        if expected == "review" {
            assert_ne!(decision, "allow", "{command}: {reason_code}");
        } else {
            assert_eq!(decision, expected, "{command}: {reason_code}");
        }
    }
}
