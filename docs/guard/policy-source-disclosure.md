# Exact policy source disclosure

Reusable policy can use an exact shell command only when its complete original
text is available with explicit local consent. Display labels, redacted text,
normalized commands, and package argument lists do not establish that source.

Source disclosure is off by default. Enable it separately with the isolated
memory operation:

```sh
hol-guard commands enable --operations guard.review.syncPolicyMemory --share-policy-source
```

Local receipt privacy must also be `none`. A stricter authenticated policy
privacy setting prevents disclosure. The flag allows complete supported shell
command text, including its original whitespace, quoting, and case, to accompany
review and receipt evidence. It does not approve a pending command or authorize
reusable policy on its own; the existing local confirmation for each memory
operation still applies.

The optional `policyMemorySource` record has contract version
`guard.policy-memory-source.v1` and carries `artifactId`, `commandText`,
`harnessId`, `localRequestId`, `workspaceId`, `installationId`,
`complete: true`, and `redaction: "none"`. It is included in the review claim hash
and in the authenticated receipt payload when current consent still permits it.
Changing or revoking the capability, changing its account or device binding,
expiration, stricter privacy, or invalid local integrity makes it unavailable.

Only unambiguous supported shell input fields qualify. Missing, synthetic,
partially available, non-shell, or oversized inputs remain unavailable. A caller
must not infer an exact command from an artifact identifier or a display field.
Source text is limited to 8192 UTF-16 code units and 32768 UTF-8 bytes. Artifact
identifiers are limited to 512 UTF-16 code units. Workspace UUIDs and bounded
installation identifiers retain their exact authenticated values.
