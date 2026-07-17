# GuardPolicy v1alpha1

GuardPolicy is HOL Guard's portable policy document. The alpha contract is intentionally narrow: YAML is the human interchange format, validated typed data is the semantic model, and RFC 8785 canonical JSON is the only representation hashed or signed.

## Normative material

- [`schema.json`](schema.json): accepted document shape and bounded extension values.
- [`semantics.md`](semantics.md): effects, matchers, lifetime, provenance, authority, and precedence.
- [`canonicalization.md`](canonicalization.md): YAML parsing profile, canonical JSON bytes, hashes, and signatures.
- [`compatibility.md`](compatibility.md): alpha versioning, extension registration, unknown fields, and deprecation policy.
- [`threat-model.md`](threat-model.md): trust boundaries, attacks, mitigations, and non-goals.
- [`rfc.md`](rfc.md): open questions for action vocabulary, scope vocabulary, trust, and local precedence.
- [`fixtures/manifest.json`](fixtures/manifest.json): valid, invalid, hash, and decision conformance vectors.

## Reference validation

The Python implementation in HOL Guard is independent of the Portal TypeScript implementation and consumes the same normative schema and fixtures.

```bash
hol-guard policy validate ./policy.yaml --json
hol-guard policy fmt ./policy.yaml --check --json
```

Run its public conformance suite from a source checkout:

```bash
uv run pytest -q tests/test_policy_document_yaml.py tests/test_policy_document_io.py tests/test_policy_document_cli.py
```

A conforming implementation must reject every fixture listed under `invalid`, parse and reformat every fixture listed under `valid` deterministically, reproduce the published canonical JSON and SHA-256 vectors byte-for-byte, and preserve all valid `x-` extensions in canonical bytes.

## Alpha status

`v1alpha1` is suitable for interoperability testing, not a stability claim. Stabilization requires an independent implementation, fixture agreement, recorded ambiguity findings, and security review. Bundle v1 and legacy policy fields remain supported during the measured compatibility window; their removal requires a separate approved proposal.
