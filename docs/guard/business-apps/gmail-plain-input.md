# Private plain-text Gmail extraction

`guard-command::business_gmail_plain::GmailPlainInputV1` consumes an owned
`GmailSendWireInputV1`. It retains the original params/body/MIME bytes and exposes
private, immutable sender, To/Cc/Bcc occurrences and exact unencoded body bytes.
There is no filesystem, shell, network, provider, review or policy operation.
These values have no Debug, Serialize, Clone or mutable interface.

This is a deliberately narrow preparation profile, not general MIME support:

- CRLF header framing; ASCII unfolded header lines of at most 998 bytes;
  at most 32 KiB of headers and 64 fields. Duplicate case-insensitive names reject.
- Allowed headers: From, To, Cc, Bcc, Subject, Date, Message-ID, MIME-Version,
  Content-Type and Content-Transfer-Encoding. Unknown headers reject.
- Exactly one bare ASCII From mailbox; at least one combined To/Cc/Bcc entry.
  Bare comma-separated dot-atom mailboxes with dotted DNS-style domains only.
  Local spelling/domain case are preserved. Every occurrence counts toward 256;
  duplicates across headers retain their original roles. `mailparse` 0.17.0
  cross-checks the bounded literal list; encoded/display/group/comment/quoted
  or obsolete address syntax is unsupported. A syntactically simple mailbox
  can still name a provider group or alias: trusted resolution remains required.
- Default ASCII text/plain, or literal `text/plain` with `charset=us-ascii` or
  `charset=utf-8`, optionally quoted. Charset spelling is case-insensitive; extra
  parameters or alternate whitespace forms are unsupported. MIME-Version, if
  present, must be `1.0`. Only 7bit/8bit transfer encodings are supported; non-ASCII
  body text requires both explicit UTF-8 and 8bit. Body text must be valid UTF-8,
  contain no NUL/Unicode controls except tab/CRLF, reject Unicode line/paragraph
  separators, use CRLF line breaks and remain
  within the 998-byte line limit. The entire wire already has a 256 KiB cap.
- Attachments, multipart, HTML, base64/quoted-printable transfer bodies, threadId,
  reply/resend/sender overrides, folding and all other shapes reject. Never catch
  these errors as a policy nonmatch or pass through the original command.

The profile commitment is SHA-256 of
`hol-guard.gmail-plain-input.v1\0` followed by the wire preparation's 64 ASCII
hex commitment bytes. Every original wire byte remains bound; this is not an
approval, dispatch token, authenticated identity or content classification.

The native owner must still inspect **all original private MIME bytes**, including
headers and body, resolve every recipient/group and the actual authenticated
From/account/tenant, apply the strongest current policy floors and bind the
prepared action to existing native private review authority. No "public" label
is inferred from parse success. Cloud must receive only approved minimal facts;
never send these mailboxes, subjects, headers or body bytes as ordinary telemetry.

General MIME/attachment support, provider identity, enforcing snapshot admission,
single-use approval, isolated credential custody and exact dispatch remain to
implement. This unused preparation API does not qualify a protected Gmail route.
