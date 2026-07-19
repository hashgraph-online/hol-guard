# Observer adapter conformance kit

HOL Guard's observer boundary is vendor-neutral. MDM, EDR, RMM, and partner adapters can run the same in-process conformance kit before certification:

```python
from codex_plugin_scanner.guard.mdm import run_observer_adapter_conformance

report = run_observer_adapter_conformance("vendor-adapter-v1", adapter.observe)
assert report.passed, report.results
```

The adapter receives bounded dictionaries and must return one of three outcomes:

- `observed` with a strict, signed `observer-assertion.v1` object;
- `collision` with `mappingStatus=ambiguous` and no assertion;
- `outage` with `errorCode=provider_unavailable` and no fabricated assertion.

The deterministic suite covers a current observation, positive clock skew, replay and duplicate idempotency, partial detection data, mapping collision, and provider outage. It verifies fixture identity binding, detection fidelity, the independent observer authority, Ed25519 signature validity, absence of fabricated remediation state, stable duplicate output, and a replay digest.

The bundled key is test-only. Production adapters must use their own independently managed observer signing credential and register only its public key with Guard Cloud. Passing this kit proves protocol conformance; it does not replace real managed-device or vendor certification.
