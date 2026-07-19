# GuardPolicy compatibility policy

## Version boundary

`apiVersion: guard.hashgraphonline.com/v1alpha1` identifies one complete schema and semantic contract. Parsers must reject an unsupported `apiVersion` or `kind`; they must not guess, silently downgrade, or merge fields from another version.

During alpha, additions are permitted only when old conforming readers already have an explicit behavior. New core fields therefore require a new API version unless they are optional and all supported readers have shipped support. A changed effect, matcher, precedence rule, canonical byte, or trust rule is incompatible and requires a new major API version.

Deprecations are announced for at least one measured support window covering active Portal and Guard client versions. Legacy bundle v1 readers and writers remain available throughout that window. Removal of legacy fields, readers, writers, or bundle v1 is out of scope for this rollout and requires a separate approved proposal.

## Unknown fields

Unknown core fields are errors. Every object in `schema.json` closes `additionalProperties` except documented free-form string maps and recursively bounded extension values. Readers must not discard an unknown core field and continue enforcement.

Extensions use names matching `^x-[a-z0-9][a-z0-9.-]{0,62}$`. Valid extension values are JSON scalars, arrays, or objects within the schema's size and depth limits. Extensions:

- survive YAML format, import, export, and canonical JSON unchanged;
- participate in the document digest and bundle signature;
- never change core matching, effect, lifetime, authority, or precedence semantics unless separately registered;
- may be ignored semantically by a reader that does not implement the registered extension, but may not be removed before hashing or forwarding.

## Extension registration

An extension proposal must publish:

1. its globally unique `x-<owner>.<name>` key;
2. allowed locations and value schema;
3. deterministic semantics and failure behavior;
4. security and privacy analysis;
5. canonical fixtures and at least one consumer;
6. a collision and retirement plan.

Registration does not grant permission to weaken core policy. An extension that changes authority, precedence, signing, or rollback requires a new core API version.

## Conformance and ambiguity

Implementations report fixture mismatches against `fixtures/manifest.json` with the fixture path, expected result, observed result, implementation version, and platform. Ambiguity findings belong in the public RFC before stabilization. No alpha behavior becomes v1.0 solely because one implementation shipped it.
