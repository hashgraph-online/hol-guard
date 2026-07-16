# GuardPolicy v1alpha1 canonicalization

## Accepted YAML subset

The parser accepts exactly one UTF-8 YAML document using YAML 1.2 JSON-compatible implicit scalars:

- implicit booleans: only `true` and `false`;
- implicit null: only `null`;
- implicit integers: JSON decimal integers; finite decimal/exponent floats are recognized and then rejected as `unsupported_float`;
- every other plain scalar, including `yes`, `no`, `on`, `off`, `~`, `0123`, sexagesimal forms, `.inf`, `.nan`, and timestamp-looking text, is a string.

Anchors, aliases, merge keys, explicit tags, custom tags, duplicate mapping keys, and multiple documents are rejected. Empty matcher arrays are rejected. Empty `match` means an explicit global rule.

Unknown core fields are rejected. `x-*` extensions are allowed at the documented object boundaries, preserved, and signed. Expressions are not a schema feature: no core field evaluates templates, environment variables, code, regular expressions, or arbitrary predicates.

## Resource limits

Validation happens before compilation:

- maximum encoded document size: 1,048,576 bytes;
- maximum nesting depth: 32;
- maximum rules: 1,000;
- maximum entries in any other collection: 256;
- maximum scalar string length: 4,096 Unicode code points;
- maximum mapping-key length: 128 Unicode code points;
- maximum returned diagnostics: 20.

A producer SHOULD use materially smaller documents. Limits are interoperability ceilings, not targets.

## Normalized model

Formatting and hashing operate on the typed normalized model, not YAML syntax. The model:

- preserves rule order and matcher-value order;
- sorts labels and extension keys;
- emits explicit `expiresAt: null` for non-expiring lifetimes;
- preserves all `x-*` values as bounded JSON data, excluding floating-point numbers;
- rejects duplicate rule IDs before construction.

The deterministic formatter emits block-style YAML, stable core-field order, UTF-8 text, LF line endings, one trailing newline, and quotes YAML-ambiguous strings. Reformatting a formatted document is byte-stable. Parsing before and after formatting produces the same normalized model and digest.

## Canonical JSON and digest

The signing/hash input is UTF-8 canonical JSON of the complete normalized document:

1. object keys sorted lexicographically by Unicode code point;
2. no insignificant whitespace;
3. JSON string escaping with unescaped non-ASCII Unicode;
4. integer numbers only;
5. all extensions included;
6. no transport wrapper, signature, or digest field included.

The schema permits only integer core numeric values, and semantic validation applies the same rule to extensions. This avoids cross-runtime floating-point serialization drift. The digest is lowercase hexadecimal `SHA-256(canonical_json_bytes)`.

This digest is independent from legacy `guard-policy-bundle.v1` `bundleHash` and `payloadHash`. Those legacy projections remain byte-for-byte unchanged until negotiated v2 activation. A consumer MUST report a disagreement between advertised and computed legacy hashes; it MUST NOT rewrite either hash as part of YAML formatting.

## Diagnostics

Diagnostics expose only a bounded stable code, JSON-style path, line, and column. Messages never echo scalar values. Callers may add filename context but MUST NOT log policy source text, secrets, credentials, authorization headers, or raw provenance payloads.
