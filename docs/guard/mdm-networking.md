# HOL Guard enterprise networking

HOL Guard always validates TLS certificates. Managed policy may select the platform system proxy, an explicit HTTPS proxy, or direct networking. An administrator-approved PEM CA bundle is added to—not substituted for—the operating system trust store. Proxy URLs containing credentials are rejected; credentialed proxies must use the operating system's approved credential mechanism.

Public registry intelligence is optional and can be disabled with `network.allowPublicRegistries=false`. Local enforcement remains active during DNS, proxy, TLS, Guard Cloud, or registry outages. The machine-readable allowlist is [mdm-endpoints.v1.json](mdm-endpoints.v1.json).

Installers are self-contained and do not contact these endpoints. Administrators should test endpoint trust from the same user or daemon context that runs Guard; user shell environment variables are not managed-policy authority.
