# Installed scoped policy proof

`probe_installed_scoped_policy.py` requires an installed native wheel, ordinary
`auto` discovery, and the existing canonical rollout setting enabled for this
invocation. Its required `--expected-source-sha` must match the verified runtime
build. It refuses source imports and native/oracle/test overrides. The
wheel matrix runs the probe on each supported platform and retains
`installed-scoped-policy.json`; a nonzero exit fails the job.

The fixture uses synthetic enrollment and a generated signing trust anchor. It
delivers actual signed policy through a certificate-verified HTTPS endpoint.
Policy rows, source capture, native capability negotiation, IPC, publication,
acknowledgements and result bindings use production code. No target command is
executed. This procedure does not establish ordinary OAuth, browser enrollment,
physical-device identity, or a combined multi-device/offline acceptance result.

The positive cases cover permanent, exact-command allow, block and review rules.
The proof retains exact-byte matching, current source and receipt bindings,
generation replacement, signature and workspace rejection, unsupported lifetime
refusal, intrinsic floors and revocation before result exposure. A raw resident
response after revocation is never accepted unless the production currentness
check accepts it; physical eviction is not assumed to be synchronous.

The base scoped capability set does not advertise managed authority, managed
configuration or command-expression extensions. Their existing negotiation
refusals remain in force. Source-only lane metadata is unchanged.

`test_installed_scoped_policy_fixture.py` checks the real signing/TLS fixture and
its refusal/privacy boundaries. These unit tests cannot substitute for a passing
installed probe. The probe's readiness clock includes registration and startup
within the existing 400 ms budget; each hook retains the existing 750 ms budget.
