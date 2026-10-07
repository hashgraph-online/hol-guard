# Private outbound credential inspection

`GoogleWorkerInput::inspect_outbound` consumes its owned, sender-authenticated
input and calls the existing Rust `guard-scanner` secret detector. It checks the
original MIME text, including headers, and the decoded plain-text body. Supported
base64 and quoted-printable transfer bodies are decoded by the existing MIME
reader before inspection. Invalid UTF-8 is refused rather than scanned lossily.
The existing bounded input profile applies, and finding collection stops at one
candidate per scanned view. No provider, model or other network call is made.

A detected credential returns a finite `CredentialDetected` error and releases
no inspected object. Private finding candidate strings are zeroized before
discard; detector internals, parser and TLS scratch are not claimed to have
complete memory-erasure guarantees. No raw candidate, body, address or finding
record is serialized or exported. Currentness is checked before and after
inspection.

The owned result binds input identity to the detector version and retains the
same immutable credential/input pair. It is not an approval or dispatch grant.
A clean scan means only that this detector found no supported credential pattern;
it cannot establish public sensitivity, financial/PII classification, full DLP,
recipient resolution, budgets, credential isolation or model-result protection.
No resident RPC or provider send path consumes the result yet. This source phase
does not qualify any installed mode or full business acceptance scenario.

Synthetic tests cover a native-scanner canary in headers, plain bodies, base64
bodies and quoted-printable bodies, plus an ordinary security discussion and
inspection binding changes. There are no live account operations.
