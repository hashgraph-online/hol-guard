# Scanner contributor pathway

## Outcome

A contributor should supply the plugin and explain its intended behavior, not become a maintainer of HOL's scanner. Scanner defects belong to HOL. A failed scan is evidence to investigate, not evidence that the contributor is malicious. Catalog admission and runtime authorization remain separate decisions.

This plan responds to the withdrawn scanner contributions #3542 and #3548 and the associated catalog submission hashgraph-online/awesome-ai-plugins#603. Do not reopen withdrawn contributions or contact their authors automatically. Generalize the demonstrated cases without adding author, repository, popularity or sponsorship allowlists.

## Invariants

- Keep the catalog's score threshold and high/critical finding gate. Do not solve a false positive with `fail_on=none`, a lower score, disabled rules, ignored source directories, or a submitter-controlled baseline.
- Keep `TRUST_REPOSITORY_POLICY=false` for centralized intake. A plugin's configuration, comments, fixtures, README and self-reported scan are untrusted input, not authority to suppress a finding.
- Never import, install, run or fetch a plugin's examples to decide whether their syntax is benign. Static analysis must not execute submitted code.
- Keep original findings, severities, score and scan failure visible when requesting review. Group repeated evidence in the review report without changing gate accounting.
- A human-reviewed false positive is not a blanket acceptance of a capability. A legitimate uploader or installer may still be inappropriate for automatic catalog admission and still needs runtime protection.
- No approval follows from an LLM explanation, bot badge, package name, file extension, or an author's claim that a value is fake.

## Two paths

### Automatic classification

Recognize narrowly demonstrated benign syntax. Every new accepted form needs nearby negative controls that differ by the dangerous operation, not a repository-specific exception.

| Input | Automatic treatment | Negative controls |
| --- | --- | --- |
| Complete fenced literal curl GET/HEAD | No upload finding for the supported retrieval syntax; not a remote-safety guarantee | Uploads, headers, userinfo, executable pipelines, substitutions, output files, config files and unknown options retain findings |
| URL authority | Explicit host, IPv6, zone and port validation | Host ranges, braces, malformed brackets, control characters and ambiguous authorities retain findings even with older Python parsers |
| URL query | Only a bounded grammar for numeric pagination and representation values | Credential keys, encoded or duplicate keys, arbitrary values and unknown query semantics retain findings |
| Complete symbolic reference | Exempt shell expansions or the reserved `$ARGUMENTS` marker at a proven expression boundary | Mixed-case password-like values, appended literals, casts, concatenation, member access and adjacent provider credentials retain findings |
| Navigation metadata | Only known password-navigation entries in bounded, flat maps whose values are mechanically key-derived | One unrelated or credential-like value invalidates the metadata exemption |
| Python inference/documentation | Pursue existing #2805 with AST-based evidence, rather than overlapping regex patches | Bare or aliased builtin eval, eval with arguments, nested calls and parse failures remain conservative |
| Synthetic credential examples | Review existing #3260 independently | A test directory or word such as example never exempts a real provider token or high-entropy value by itself |

One curl command with multiple URL operands is outside the initial automatic exemption. Several independent retrieval examples in a complete bounded fence may be classified individually only when the entire fence remains understood. Unsupported syntax remains reviewable rather than silently safe.

### Maintainer-owned review

1. The centralized scan produces its ordinary full report, scanner version, target revision, scan policy and failure reason. A contributor review section groups exact duplicate evidence for readability and states that it does not grant approval.
2. The contributor supplies intended behavior and a minimal reproducer in the existing submission PR. Never request a real secret in a public comment. No new scanner installation in the contributor's repository is required.
3. HOL assigns one maintainer to distinguish a detector defect, a genuine risky capability, a source problem, or a scanner/infrastructure failure. Keep the existing submission open while correcting HOL-owned problems, unless the contributor withdraws it.
4. A detector defect is reproduced against a pinned scanner and becomes a positive regression plus adversarial controls in the scanner repository. HOL supplies the patch and validation; the contributor does not have to submit a replacement scanner PR.
5. Genuine secrets, execution chains, source-integrity failures, malicious behavior and unverified external-analyzer findings remain blocked. Explain the concrete remediation rather than asking contributors to alter unrelated documentation to satisfy a keyword search.
6. Merge and release the tested scanner correction through its usual protected workflow. Update every catalog's immutable Action/scanner pin and rerun the centralized scan against the contributor's exact revision. A local candidate scan does not satisfy the catalog gate.
7. Admit only on a verified final scan or a separately implemented and security-reviewed adjudication mechanism. This patch does not introduce manual bypasses.

## Future exact-evidence adjudication, not an implicit bypass

A temporary adjudication lane may be useful while a released detector fix propagates, but it is NOT enabled by this implementation. Before enabling it, require all of the following:

- Decisions are stored in a protected maintainer-owned repository, not in the plugin or a PR-controlled workflow. Separate approval and scan permissions; no privileged execution of contributor content.
- Bind each decision to repository identity, exact source commit, relative path, full file digest, rule and detector version, policy version, evidence span, disposition, reviewer, review URL and expiry.
- Accept only explicitly proven false positives for reviewed rule families. Intended risky capabilities, actual credentials, unverified findings and missing analyzers are not automatically waivable.
- Verify the whole source snapshot before and after scanning. Reject changed files, stale revisions, renamed files, altered evidence, expired decisions, duplicate keys, malformed decisions and missing fields.
- Preserve raw findings and scores. Show reviewed evidence separately and make the catalog decision transparent. Never publish a 'clean scan' badge for a scan with adjudicated exceptions.
- Enforce fail-closed handling of missing or unverifiable review records. A new release, new finding or source change requires revalidation. Reviewer independence must be enforced by the actual protected workflow, not a JSON field.
- Test the integration through the production admission consumer before rollout. Do not ship only a JSON schema or helper and claim that the review lane is operational.

## Contributor CI and release ownership

The maintainer-owned correction branch avoids requiring fork contributors to repeatedly rewrite history or wait for workflow approval. On genuine fork PRs, a maintainer should promptly inspect workflow changes and authorize unprivileged checks; never move execution to `pull_request_target` with credentials to avoid that approval.

Secret-scanning test vectors should be clearly synthetic and constructed at runtime where appropriate. If a committed fixture triggers Gitleaks, verify the exact finding first. Any unavoidable fixture exception must be bound to the precise path and bytes and accompanied by controls proving that a different value in the same file and the same value outside the fixture remain detected. Do not ask contributors to withdraw and recreate PRs merely to clear a fixture finding.

Catalog scanner pin synchronization is part of the release definition of done. Treat missing workflow-write permissions as a failed infrastructure handoff, not a plugin failure. Do not mark a source safe or lower thresholds to conceal a stale scanner pin.

## Acceptance and rollout

- Run both scanner consumers and helpers against benign, dangerous, malformed and resource-boundary cases. Assert that the production high-severity gate still fails for every dangerous control.
- Run existing scanner, policy, Action reporting, secret, skill-security and regex-equivalence tests under the normal repository configuration with generated native projections. Isolated helper runs are supplemental evidence, not a substitute.
- Compare the candidate with the released scanner on pinned, unchanged repositories without executing their content, uploading data, probing URLs or auto-submitting anything. Investigate every removed high-finding location; do not optimize merely for a higher score.
- Keep JavaScript/TypeScript eval heuristics, Cisco findings, runtime Rust authority, dependencies, severity policy and submission rules unchanged unless separately reviewed.
- Required CI and substantive code review must pass on the exact final commit. Merge the scanner PR, publish normally, update immutable intake pins, and verify the first centralized rescans before calling the rollout complete.
- Measure time to first actionable response, time awaiting HOL-owned scanner fixes, withdrawn submissions, verified false-positive removals and adversarial detection retention. Do not claim a conversion improvement before measuring it.

## Implementation checklist

- [x] Implement bounded curl and symbolic-value classification with negative controls on this branch.
- [x] Add report-only contributor review guidance without changing policy or submission outcomes.
- [ ] Reconcile #2805 and #3260 as separate reviewed changes; do not silently duplicate or merge them.
- [ ] Pass normal-configuration scanner regressions and required CI on the final commit.
- [ ] Publish a scanner release and repair/verify downstream immutable pin updates.
- [ ] Rerun remaining willing contributors' centralized scans on pinned source revisions.
- [ ] Enable any temporary adjudication lane only after the requirements above are implemented and independently reviewed.

## Current implementation evidence

The contributor-review payload is report-only. It groups exact duplicate Finding records and repeats trusted maintainer instructions in JSON, Markdown and Action summaries. It does not read a decision file, grant admission, delete findings, reduce severity or change score accounting. Group numbers are report-local and are explicitly not source-bound attestations.

The initial query grammar accepts exactly one literal pagination or representation field. Multiple fields, encodings, unrecognized keys and arbitrary values retain findings. The original linear command/URL matcher is unchanged; bounded retrieval recognition lives in a separate module.

The context-classification foundation and its original regression corpus derive from Seth Hobson's withdrawn #3548. This maintainer branch adds stricter URL/expression boundaries and review reporting; it does not imply that the contributor endorsed these additions. Neither withdrawn PR is reopened.

Parenthesized generic secret assignments and quoted JSON keys remain known baseline detector gaps, not newly exempted cases. The new controls assert findings only where the existing detector recognizes the assignment, while proving that continued expressions cannot gain a new exemption. Existing #2805 and #3260 remain separately scoped work.

Review hardening limits non-shell literals to the reserved `$ARGUMENTS` marker; uppercase spelling alone is not an environment reference. General `$NAME` syntax requires a shell file or a demonstrable shell-option context. Navigation exemptions cover only known password-navigation entries, never adjacent `Secret` or `Token` fields. Contributor review groups retain category, title, description and remediation so distinct evidence at the same location is not ambiguous. These strings are untrusted report data, not instructions or approvals.
