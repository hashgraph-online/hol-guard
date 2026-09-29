//! Closed ownership contracts for existing native compatibility behavior.

const CAPABILITIES: &[(&str, &str, &str)] = &[
    (
        "command.container-runtime",
        "command.container-runtime.docker-sensitive",
        "command.container-runtime.permission.docker-sensitive",
    ),
    (
        "command.container-runtime",
        "command.container-runtime.docker-config-access",
        "command.container-runtime.permission.docker-config-access",
    ),
    (
        "command.data-protection",
        "command.data-protection.credential-exfiltration",
        "command.data-protection.permission.credential-exfiltration",
    ),
    (
        "command.data-protection",
        "command.data-protection.file-upload",
        "command.data-protection.permission.file-upload",
    ),
    (
        "command.git",
        "command.git.unverified-fetch",
        "command.git.permission.unverified-fetch",
    ),
    (
        "command.git",
        "command.git.index-inspection",
        "command.git.permission.index-inspection",
    ),
    (
        "command.git",
        "command.git.branch",
        "command.git.permission.branch",
    ),
    (
        "command.git",
        "command.git.pull",
        "command.git.permission.pull",
    ),
    (
        "command.git",
        "command.git.push",
        "command.git.permission.push",
    ),
    (
        "command.git",
        "command.git.clone",
        "command.git.permission.clone",
    ),
    (
        "command.git",
        "command.git.fetch",
        "command.git.permission.fetch",
    ),
    (
        "command.git",
        "command.git.remote",
        "command.git.permission.remote",
    ),
    (
        "command.git",
        "command.git.status",
        "command.git.permission.status",
    ),
    (
        "command.git",
        "command.git.log",
        "command.git.permission.log",
    ),
    (
        "command.git",
        "command.git.diff",
        "command.git.permission.diff",
    ),
    (
        "command.git",
        "command.git.show",
        "command.git.permission.show",
    ),
    (
        "command.git",
        "command.git.blame",
        "command.git.permission.blame",
    ),
    (
        "command.git",
        "command.git.grep",
        "command.git.permission.grep",
    ),
    (
        "command.git",
        "command.git.describe",
        "command.git.permission.describe",
    ),
    (
        "command.git",
        "command.git.ls-files",
        "command.git.permission.ls-files",
    ),
    (
        "command.git",
        "command.git.reflog",
        "command.git.permission.reflog",
    ),
    (
        "command.github",
        "command.github.routine-merge",
        "command.github.permission.routine-merge-remote",
    ),
    (
        "command.github",
        "command.github.workflow-mutation",
        "command.github.permission.routine-workflow-remote",
    ),
    (
        "command.github",
        "command.github.local-write",
        "command.github.permission.write-local",
    ),
    (
        "command.github",
        "command.github.maintenance",
        "command.github.permission.maintain-remote",
    ),
    (
        "command.github",
        "command.github.content",
        "command.github.permission.content-remote",
    ),
    (
        "command.github",
        "command.github.merge",
        "command.github.permission.merge-remote",
    ),
    (
        "command.github",
        "command.github.admin-merge",
        "command.github.permission.merge-admin",
    ),
    (
        "command.github",
        "command.github.publish",
        "command.github.permission.publish-remote",
    ),
    (
        "command.github",
        "command.github.workflow",
        "command.github.permission.workflow-remote",
    ),
    (
        "command.github",
        "command.github.force",
        "command.github.permission.force-remote",
    ),
    (
        "command.github",
        "command.github.delete",
        "command.github.permission.delete-remote",
    ),
    (
        "command.github",
        "command.github.secret",
        "command.github.permission.secret-remote",
    ),
    (
        "command.github",
        "command.github.access",
        "command.github.permission.access-remote",
    ),
    (
        "command.github",
        "command.github.mutation",
        "command.github.permission.mutate-remote",
    ),
    (
        "command.github",
        "command.github.unknown",
        "command.github.permission.unknown",
    ),
    (
        "command.kubernetes-secrets",
        "command.kubernetes-secrets.secret-read",
        "command.kubernetes-secrets.permission.secret-read",
    ),
    (
        "command.shell-mutations",
        "command.shell-mutations.destructive-shell",
        "command.shell-mutations.permission.destructive-shell",
    ),
    (
        "command.shell-mutations",
        "command.shell-mutations.managed-config-write",
        "command.shell-mutations.permission.managed-config-write",
    ),
    (
        "command.shell-mutations",
        "command.shell-mutations.sensitive-file-write",
        "command.shell-mutations.permission.sensitive-file-write",
    ),
    (
        "command.shell-mutations",
        "command.shell-mutations.process-environment-secret-read",
        "command.shell-mutations.permission.process-environment-secret-read",
    ),
    (
        "command.shell-mutations",
        "command.shell-mutations.github-body-substitution",
        "command.shell-mutations.permission.github-body-substitution",
    ),
];

pub(super) fn valid_scope(extension: &str, executables: &[String]) -> bool {
    let scopes: &[(&str, &[&str])] = &[
        ("command.container-runtime", &[]),
        ("command.data-protection", &[]),
        ("command.git", &[]),
        ("command.github", &[]),
        ("command.kubernetes-secrets", &[]),
        ("command.shell-mutations", &[]),
    ];
    scopes.iter().any(|(id, names)| {
        *id == extension
            && names.len() == executables.len()
            && executables
                .iter()
                .all(|name| names.contains(&name.as_str()))
    })
}

pub(super) fn valid_binding(
    capability: &str,
    extension: &str,
    rule: &str,
    permission: &str,
) -> bool {
    capability.strip_suffix(".v1") == Some(rule)
        && CAPABILITIES.contains(&(extension, rule, permission))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn closed_contracts_account_for_every_native_compatibility_rule() {
        let known: BTreeSet<_> = crate::command_compatibility::compatibility_rule_ids()
            .iter()
            .copied()
            .collect();
        let bound: BTreeSet<_> = CAPABILITIES.iter().map(|row| row.1).collect();
        assert_eq!(bound, known);
        assert_eq!(bound.len(), CAPABILITIES.len());
        let program: serde_json::Value =
            serde_json::from_slice(super::super::EMBEDDED_PROGRAM).unwrap();
        for (extension, rule, permission) in CAPABILITIES {
            let row = program["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["rule_id"] == *rule)
                .unwrap();
            assert!(row["matcher"].is_null());
            assert_eq!(row["extension_id"], *extension);
            assert_eq!(row["permission_id"], *permission);
            assert!(valid_binding(
                &format!("{rule}.v1"),
                extension,
                rule,
                permission
            ));
            assert!(!valid_binding(
                &format!("{rule}.v2"),
                extension,
                rule,
                permission
            ));
            assert!(!valid_binding(
                &format!("{rule}.v1"),
                extension,
                rule,
                "command.forged.permission.owner"
            ));
        }
    }
}
