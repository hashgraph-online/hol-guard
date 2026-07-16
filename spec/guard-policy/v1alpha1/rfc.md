# RFC: GuardPolicy v1alpha1 interoperability

Status: public alpha; comments requested through a GitHub issue or pull request against this document.

## Proposal

Adopt `guard.hashgraphonline.com/v1alpha1` as the shared human-authored policy contract for Portal and HOL Guard. YAML is input and display only. Validated typed data is canonicalized as RFC 8785 JSON for hashing and signing. Legacy bundle v1 remains available during the compatibility window.

## Questions for implementers

### Action vocabulary

The core effects are `allow`, `block`, `review`, and `ignore`. Are these sufficient across shell, file, browser, MCP, package, skill, plugin, and remote-control actions? Should a future version distinguish advisory review from an enforcement pause without changing precedence?

### Scope vocabulary

The alpha matcher vocabulary covers operations, actors, agents, artifacts, commands, devices, domains, ecosystems, environments, harnesses, locations, MCPs, packages, paths, publishers, repositories, secret types, skills, tools, workspaces, and browser-specific fields. Which fields are ambiguous across runtimes? Which missing scopes cannot be expressed safely as a registered extension?

### Trust

A signed cloud bundle is accepted only through a local trusted-key registry. Is RSA-PSS/SHA-256 sufficient for the compatibility window? What rotation, revocation, offline grace, and emergency rollback evidence should a stable version require?

### Local precedence

Current precedence evaluates eligibility, local/remote authority, exactness/specificity, then recency. Does an exact local temporary decision always need to beat a broader remote rule? Which managed environments require an explicit non-overridable remote authority, and should that be a new API version rather than an extension?

## Review evidence requested

Implementers should run `fixtures/manifest.json`, report canonical byte/hash differences, and attach effective-decision results for local/remote, exact/broad, active/expired, and once/permanent cases. Reports must identify parser version and platform without including private policy content.

## Stabilization criteria

- at least two independent implementations agree on every fixture;
- ambiguity findings are resolved in the normative semantics;
- a security review covers YAML parsing, extensions, canonicalization, signing, trust, rollback, precedence, and secret handling;
- staged production metrics show no unexplained legacy/canonical decision mismatch;
- compatibility and deprecation windows are approved.

Until those gates pass, the contract remains `v1alpha1`; incompatible changes use a new API version rather than silent reinterpretation.
