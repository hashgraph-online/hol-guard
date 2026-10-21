# Private Google worker input

`GoogleSendCredential::prepare_command` consumes its credential and the original
POSIX command. It uses the existing narrow `gws gmail users messages send` inline
parser and strict single-part plain MIME reader, then authenticates the exact
MIME From mailbox against the credential's signed verified Google mailbox.
Expired credentials, another sender, send-as aliases and unsupported command or
MIME forms are refused. Errors contain no account, address, command or body text.
Expired credentials return a distinct `Expired` error so setup can request
reauthorization; mismatched mailboxes return `Sender`.

The resulting non-cloneable, non-serializable `GoogleWorkerInput` owns the
credential and immutable decoded input together. Its digest commits the original
command binding, decoded MIME binding, account binding and tenant binding.
Inspection getters are for the private worker only. They must not be copied into
Cloud metadata or presented as model-supplied permission. Neither the credential
nor the original shell command can be extracted from this object. Currentness is
checked again through the owned credential; the object has no dispatch method.

This pairing does not prove a resolved executable, named-recipient or group
expansion, content inspection, budgets, policy admission, account enrollment,
credential isolation or permission to send. No public RPC, private review request
producer, refresh or provider dispatch is added. Those remain required before the
business journey can pass acceptance. Tests use synthetic signed identities and
owned command/MIME bytes; no live Google account or agent qualification is claimed.

Primary sender claims follow the [Google OIDC reference](https://developers.google.com/identity/openid-connect/reference).
