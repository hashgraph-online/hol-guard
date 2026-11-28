# Secret provider contributions

Secret provider contributions use guard.secret-provider.v1 and remain external and disabled until a local
administrator enables them. The provider contract, threat model, fixture requirements and validation flow are
documented in docs/guard/secret-management-provider-contributing.md.

Use synthetic fixture values and hosts. Provider manifests cannot execute commands, load downloaded code,
choose arbitrary hosts, allow redirects, or receive secret values through telemetry.
