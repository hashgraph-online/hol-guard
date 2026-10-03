# MCPB release tool

Install the locked dependencies with `npm ci --ignore-scripts`, then run
`node harden-forge.cjs` before invoking the MCPB CLI. Both MCPB workflows enforce
this order. The tool is a build dependency and is not included in Guard packages.

The locked Forge 1.4.0 has an incomplete RSA DigestInfo validation fix
([upstream report](https://github.com/digitalbazaar/forge/issues/1149)).
The local backport accepts only an OID followed by an optional primitive, empty
NULL in the AlgorithmIdentifier. It rejects extra elements and malformed NULLs.
It verifies the complete original `rsa.js` SHA-256 before patching, rejects
unrecognized source or versions, and supports idempotent invocation.

Each invocation tests canonical RSA signatures, an incorrect digest, and three
malformed AlgorithmIdentifiers. `verify-forge.cjs` fails on the original package.
Only a successful backport and regression check can generate the OpenVEX record.
The security workflow applies that record solely to the MCPB tool directory;
the rest of the repository is scanned separately without it. Other advisories
remain blocking. The lock retains the upstream version, so registry-only audits
cannot infer that the local source has been patched.

Remove the backport after a corrected upstream release is pinned and the same
negative verification cases pass against it. A version change fails the current
backport gate and requires explicit review.
