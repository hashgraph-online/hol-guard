# GuardPolicy specification

`GuardPolicy` is HOL Guard's portable policy source format.

- [v1alpha1 JSON Schema](v1alpha1/schema.json)
- [v1alpha1 semantics](v1alpha1/semantics.md)
- [v1alpha1 canonicalization](v1alpha1/canonicalization.md)
- [v1alpha1 conformance fixtures](v1alpha1/fixtures)
- [Deferred legacy removal PRD](legacy-removal-prd.md)

Versions are additive during alpha. A consumer MUST reject an unknown `apiVersion`; it MUST NOT guess or silently downgrade. The public schema and fixtures are normative. The Python package carries an exact generated schema copy for installed CLI validation, and its contract test prevents drift.

The format is repository-neutral. Private endpoints, infrastructure names, credentials, internal topology, and deployment details do not belong in this directory or its fixtures.
