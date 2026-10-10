# Code review policy

## File-size guidance

Apply the repository's 500-line maintainability guideline to source-code files, not declarative JSON.

Never report a `*.json` file as too large based only on line count or file size, and never require JSON to be split solely to satisfy the 500-line guideline. This includes extension sources, fixtures, generated JSON, schemas, manifests, and contracts.

Continue reviewing JSON for correctness, security, schema validity, trust-boundary mistakes, contradictory or duplicated data, and unnecessary generated churn.
