//! Mandatory policy floors for direct secret reads and incomplete local-code
//! inspection (`runtime/command_shell_read_factors.py`, 33 lines — verbatim).

use std::path::Path;

use crate::effect_decision::{DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction};
use crate::shell_secret_reads::assess_shell_reads;

/// `shell_read_floor_factors` (:13-33). Review floors only — never execution
/// authorization or positive proof.
pub fn shell_read_floor_factors(
    command_text: &str,
    security_identity: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<DecisionFactor> {
    let assessment = assess_shell_reads(command_text, cwd, home_dir);
    if !assessment.requires_review() {
        return Vec::new();
    }
    let reason_code = if !assessment.sensitive_paths.is_empty() {
        "critical.local-secret-read"
    } else {
        "critical.local-script-execution"
    };
    vec![DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: reason_code.to_owned(),
        basis: DecisionBasis {
            action_floor: GuardAction::RequireReapproval,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: Some(format!(
            "operation:{}",
            security_identity.rsplit(':').next().unwrap_or("")
        )),
        producer_ref: Some("runtime:shell-read-floors-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::shell_read_floor_factors;
    use std::path::PathBuf;

    const ORACLE: &[(&str, Option<&str>)] = &[
        ("ls -la", None),
        ("cat ~/.ssh/id_rsa", Some("critical.local-secret-read")),
        ("cat ~/.env", Some("critical.local-secret-read")),
        ("cat .env", Some("critical.local-secret-read")),
        ("bash script.sh", Some("critical.local-script-execution")),
        ("sh -c 'echo hi'", None),
        ("echo hello", None),
        (
            "cat ~/.ssh/id_rsa && ls",
            Some("critical.local-secret-read"),
        ),
        ("python script.py", Some("critical.local-script-execution")),
        ("cat /tmp/nonexistent_file_xyz", None),
        ("cat ~/.aws/credentials", Some("critical.local-secret-read")),
        (
            "head -1 ~/.ssh/id_ed25519",
            Some("critical.local-secret-read"),
        ),
        ("cat ~/.netrc", Some("critical.local-secret-read")),
        ("source ~/.zshrc", Some("critical.local-script-execution")),
        (". ./config.sh", Some("critical.local-script-execution")),
        ("cat ~/secrets/token.txt", None),
        (
            "sleep 1 && cat ~/.ssh/id_rsa",
            Some("critical.local-secret-read"),
        ),
        (
            "cat $(echo ~/.ssh/id_rsa)",
            Some("critical.local-script-execution"),
        ),
        (
            "bash -c 'cat ~/.ssh/id_rsa'",
            Some("critical.local-secret-read"),
        ),
        (
            "cat ~/.ssh/id_rsa | wc -l",
            Some("critical.local-secret-read"),
        ),
    ];

    #[test]
    fn shell_read_floor_factors_python_oracle() {
        let home = PathBuf::from("/tmp/rtm008-home");
        std::fs::create_dir_all(home.join(".ssh")).ok();
        std::fs::write(home.join(".env"), "SECRET=x").ok();
        std::fs::write(home.join(".ssh/id_rsa"), "KEY").ok();
        std::fs::write(home.join("script.sh"), "echo hi").ok();
        std::fs::create_dir_all("/tmp/.ssh").ok();
        std::fs::write("/tmp/.env", "SECRET=x").ok();
        std::fs::write("/tmp/script.sh", "echo hi").ok();
        std::fs::write("/tmp/.zshrc", "echo z").ok();
        std::fs::write("/tmp/config.sh", "echo c").ok();
        std::fs::create_dir_all("/tmp/secrets").ok();
        std::fs::write("/tmp/secrets/token.txt", "t").ok();

        let cwd = PathBuf::from("/tmp");
        for (command, want_reason) in ORACLE {
            let factors = shell_read_floor_factors(command, "guard:shell", Some(&cwd), Some(&home));
            let got_reason = factors.first().map(|f| f.reason_code.as_str());
            assert_eq!(
                got_reason, *want_reason,
                "parity mismatch for {command:?}: got {factors:?}"
            );
        }
    }
}
