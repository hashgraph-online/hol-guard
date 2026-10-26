# File-size review policy

The 500-line maintainability guideline applies to source-code files only.

For every `*.json` file, ignore line-count and file-size thresholds. Do not report a JSON file as oversized, require it to be split, or propose a mechanical split solely because it exceeds 500 lines.

This exception includes declarative command-extension sources, portable fixtures, generated JSON, schemas, manifests, contracts, and other JSON data.

Still review JSON for correctness, schema validity, security, trust decisions, matcher behavior, duplicated or contradictory entries, and unnecessary generated churn.

Continue enforcing the source-code file-size guideline where appropriate.
