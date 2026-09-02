# Everyday Mode semantic explanation catalog

HOL Guard Core owns action meaning. The catalog is deterministic, local, bounded, and side-effect free. It consumes typed facts from the canonical action envelope and `CanonicalCommand`; it never executes commands, performs network requests, or calls a language model. Policy outcomes may add reason context, but they do not determine what an action means.

## Covered families in EVM-101–200

The first runtime slice covers ordered compound commands; recursive and ordinary file deletion; file copy, move, and rename; ownership and permission changes; exact credential-file reads; outbound web requests, downloads, uploads, and remote transfer; package installation, removal, and publication; and safe unknown-action fallback. File, network, package, remote, and credential targets prefer typed Core facts before bounded executable-specific fallback logic.

Every recognized action has a consequence-first headline, plain-language summary, material impact, recommendation, typed target list, typed consequence list, and safer alternatives. Unknown or unsupported actions are `limited` confidence and are never inferred safe. Compound actions preserve execution order and expose individual material steps without changing enforcement.

## Identity and compatibility

Every explanation binds `action_identity`, optional `canonical_identity`, semantic `catalog_digest`, renderer version, locale, and redaction version. Cache keys cover all of those values. A consumer must reject or visibly degrade an explanation when the action or canonical identity no longer matches the request being rendered. The semantic catalog digest covers every rule field that can affect rendered output.

## Privacy and retention

Everyday text uses bounded safe target labels rather than full local paths. Network actions retain a safe destination host while secret-bearing payload values are redacted separately. Credential targets are identified only from exact sensitive filename/path patterns, avoiding substring guesses such as `secretary.txt` or `tokenizer.py`.

Technical values pass through Guard's existing redaction service, including bearer, API, GitHub, AWS, npm, private-key, environment-secret, password, and connection-string handling. Exact commands are available only when Core retained them and the caller is authorized to see them. List and Cloud consumers use the contract projections that strip exact command text, arguments, segments, and working-scope details.

## Extension metadata

Extension explanation metadata is presentation-only. It may contribute everyday names, purposes, synonyms, dialect coverage, action-intent IDs, target kinds, consequence IDs, safer-step IDs, and safe-variant IDs. The parser rejects enforcement/decision fields, rollback revisions, invalid schemas, unbounded values, and rules that suppress all consequences. Built-in command rules require explanation metadata or an explicit generic fallback before release.
