use crate::pretool::evaluate_pre_tool_with_context;
use crate::CommandModelRequestV1;

fn decide(command: &str) -> (String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let request = CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision = evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    (decision.minimum_action, decision.reason_code)
}

/// The read-only proof above the word is what makes it a namespace, so every
/// invocation that proof admits keeps its allow: a listing, and a help read
/// that prints the subcommand's help and runs nothing.
#[test]
fn a_proven_read_only_gh_secret_invocation_reads_as_metadata() {
    for command in [
        "gh secret list",
        "gh secret list --env preview",
        "gh secret --help",
        "gh secret set EXAMPLE_TOKEN --help",
        "gh secret delete EXAMPLE_TOKEN --help",
        "gh --repo owner/name secret list",
    ] {
        let (action, code) = decide(command);
        assert_eq!(action, "allow", "{command}: {code}");
    }
}

/// Only the namespace word is metadata. A command that reaches a secret, and
/// an operand that spells one, both keep the ordinary sensitive screen.
#[test]
fn a_secret_beyond_the_namespace_still_reaches_review() {
    for command in [
        "gh secret set EXAMPLE_TOKEN",
        "gh secret delete EXAMPLE_TOKEN",
        "gh secret set MY_SECRET --help",
        "gh secret list --show-token",
    ] {
        let (action, _) = decide(command);
        assert_ne!(action, "allow", "{command}");
    }
}
