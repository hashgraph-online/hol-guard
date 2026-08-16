# Local risk report security review

Reviewed scope: the local `risk-report` generator, JSON/HTML rendering, integrity digest, CLI output path, and privacy boundary.

## Security requirements

- The generator must not perform a network request.
- Unknown fields in the source status payload must not flow into output.
- Prompts, commands, source code, raw findings, paths, host/user identifiers, credentials, and raw receipts are prohibited from the report.
- HTML output is local and carries `noindex,nofollow`.
- The report must state that it is not a certification.
- The SHA-256 digest is an integrity checksum only. It must not be described as signer identity, remote attestation, or proof of an uncompromised host.
- A report that changes any covered sanitized field must fail integrity verification.

## Abuse review

The local generator has no report lookup endpoint and therefore no remotely enumerable identifier. It accepts no remote input and follows no file references from the status payload. The only output destinations are stdout or a path selected by the local operator.

If a separate cloud sharing feature stores these reports, that feature must provide its own explicit consent, opaque identifiers, authorization, expiry, revocation, enumeration resistance, and public/private publication controls. Those controls are not delegated to the local generator.

## Decision

The local report is suitable to ship when its redaction, tamper-detection, parser, and normal repository checks pass. Public sharing must remain a separate opt-in boundary.
