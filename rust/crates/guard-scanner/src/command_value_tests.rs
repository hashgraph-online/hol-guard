use super::is_command_substitution;
use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

// Built at runtime so secret scanners do not read the test source as a leak.
const SAMPLE: &str = concat!("Kq7xY2mN", "9pL4vR8tW3sZ");

fn credential_assignment(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

#[test]
fn a_credential_read_from_a_command_is_not_a_leak() {
    for text in [
        "export GH_TOKEN=$(gh auth token --user someone)\n",
        "GH_TOKEN=$(gh auth token) gh pr list\n",
        "API_KEY=\"$(op read op://app/api/key)\"\n",
        "TOKEN=$(cat ~/.config/app/token)\n",
        "SECRET_KEY=$(openssl rand -hex 32)\n",
        "token=$(aws ssm get-parameter --name /app/token --with-decryption --query Parameter.Value --output text)\n",
        "password=$(security find-generic-password -s app -w); export password\n",
        "DB_PASSWORD=$(kubectl get secret db -o jsonpath={.data.password} | base64 -d)\n",
        "git -c \"credential.helper=!f() { echo username=someone; echo password=\\$(gh auth token --user someone); }; f\" push origin HEAD\n",
        "AUTH_TOKEN=$(head -c 32 /dev/urandom | sha256sum | cut -c1-64)\n",
    ] {
        assert!(!credential_assignment(text), "{text}");
    }
}

#[test]
fn a_command_that_carries_a_literal_stays_flagged() {
    for text in [
        format!("TOKEN=$(echo {SAMPLE})\n"),
        format!("TOKEN=$(printf %s {SAMPLE})\n"),
        format!("TOKEN=$(/bin/echo {SAMPLE})\n"),
        format!("TOKEN=$(X=1 echo {SAMPLE})\n"),
        format!("TOKEN=$(gh auth token; echo {SAMPLE})\n"),
        format!("TOKEN=$(true | echo {SAMPLE})\n"),
        format!("TOKEN=$(decode {SAMPLE})\n"),
        format!("TOKEN=$(decode --key={SAMPLE})\n"),
        "TOKEN=$(decode Kq7x-Y2mN-9pL4-vR8t)\n".to_string(),
        "TOKEN=$(decode 3f2a9c1e-4b5d-4e6f-8a7b-9c0d1e2f3a4b)\n".to_string(),
        format!("TOKEN=$(tool \"{SAMPLE}\")\n"),
        format!("TOKEN=$(base64 -d <<< {SAMPLE})\n"),
        format!("TOKEN=$(gh auth token){SAMPLE}\n"),
        format!("TOKEN=\"$(gh auth token){SAMPLE}\"\n"),
        format!("TOKEN=$(gh auth token {SAMPLE}\n"),
        format!("TOKEN=$(tool $(echo {SAMPLE}))\n"),
    ] {
        assert!(credential_assignment(&text), "{text}");
    }
}

#[test]
fn only_a_closed_substitution_after_the_separator_counts() {
    assert!(is_command_substitution("TOKEN=$(gh", " auth token)"));
    assert!(is_command_substitution("TOKEN=\"$(gh", " auth token)\""));
    assert!(!is_command_substitution("TOKEN=\"$(gh", " auth token)"));
    assert!(!is_command_substitution("TOKEN=$(gh", " auth token"));
    assert!(!is_command_substitution("TOKEN=x$(gh", " auth token)"));
    assert!(!is_command_substitution("TOKEN", " $(gh auth token)"));
    let long = format!("TOKEN=$(tool {})", "a ".repeat(400));
    assert!(!is_command_substitution(&long, ""));
}

/// The Gauntlet fixture `portal/scripts/open-release-pr.sh`, read whole.
#[test]
fn a_release_script_that_reads_its_tokens_from_tools_reads_clean() {
    let script = r##"#!/usr/bin/env bash
# Opens the weekly release pull request with tokens read from local tools.
set -euo pipefail

export GH_TOKEN=$(gh auth token)
REGISTRY_TOKEN="$(op read op://release/registry/token)"
SIGNING_KEY=$(security find-generic-password -s release-signing -w)
export REGISTRY_TOKEN SIGNING_KEY

git -c "credential.helper=!f() { echo username=release-bot; echo password=\$(gh auth token); }; f" push origin HEAD
gh pr create --fill --base main
"##;
    let result = scan_text(script, true, true, MAX_SCAN_BYTES, None);
    assert!(
        result.matches.is_empty(),
        "{:?}",
        result
            .matches
            .iter()
            .map(|m| &m.classifier)
            .collect::<Vec<_>>()
    );
}
