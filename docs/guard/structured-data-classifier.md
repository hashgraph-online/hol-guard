# Declared sensitive-data classifier

`runtime.structured_data_sensitivity.classify_declared_content` is an opt-in,
local presence classifier. No host adapter calls it yet. Its results do not
block, redact, or replace bytes sent to a tool or model.

The classifier reuses Guard's existing credential patterns through the bounded
hook content scanner. For personal data, the caller declares exact JSON object
paths and their roles. It does not infer that every email address, name, or
contact-like string is protected personal data.

```python
from codex_plugin_scanner.guard.runtime.structured_data_sensitivity import (
    DeclaredField,
    DeclaredSchema,
    classify_declared_content,
)

schema = DeclaredSchema(
    fields=(
        DeclaredField(("employee", "email"), "protected_personal", category="email_address"),
        DeclaredField(("note",), "ordinary"),
    )
)
result = classify_declared_content(
    b'{"employee":{"email":"sample@example.invalid"},"note":"ordinary contact"}',
    schema=schema,
)
assert result.status == "matched"
```

`matched` means at least one declared rule found a value. `no_declared_match`
means no match under these particular rules; it is not a general safety
verdict. `unsupported` means this classifier could not completely classify the
input. Callers requiring a strict data policy must withhold or review
`unsupported` content. A `complete=False` result is never sufficient to claim
that all categories were checked. Matches contain category, sensitivity,
declared field path, and a static reason. They contain no matched value,
sample, or content hash. The rule version hashes only rule definitions.

The fixed limits are 64 KiB of UTF-8 input, eight object levels, 128 visited
nodes, 64 scalar fields, and 16 returned matches. A 200 ms deadline is checked
between scanner chunks and object nodes; individual regex and JSON parser
calls are not preempted mid-call.
Oversize, expired, malformed, duplicate-key, unknown-field, wrong-type, array,
and escaped input is `unsupported`. This includes otherwise valid JSON with
escaped backslashes or quotes; the credential scan sees raw input and cannot
claim complete coverage after decoding. Empty or whitespace-only strings in
declared personal fields count as absent; integer zero counts as present. The
closed schema currently permits exact
object paths with string or integer leaves. Streaming, binary attachments,
compressed or encoded payloads, arbitrary arrays, and free-form personal-data
inference are outside this contract. No bytes may be forwarded based on this
result alone; the actual mediated boundary must decide what happens to them.

Credential patterns can flag benign examples or miss unfamiliar formats.
The existing local-content sample handling is reused, and a schema can cause
a benign value in a declared protected field to count as a match. Conversely,
an ordinary field can contain contact-like text without a personal-data match.
This classifier does not separate tool authentication headers from outgoing
content, inspect final serialized model requests, or prove downstream
redaction. Those behaviors need explicit mediation and receiver tests.
