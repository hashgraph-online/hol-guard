The adjacent `extension-distribution-provenance.sigstore.json` is a public
GitHub Actions Sigstore bundle from this repository's extension artifact
publication workflow. Its source commit is
`ffa0eaa6ac9a1ca8daaa18cc587937dbd501cfd5`; its manifest subject is
`extension-artifacts.v1.json`, SHA-256
`cdd0fb6a3cf407fc3947a5423747b7e5409479db5b02b1c3d441d9d9a4b501ac`.

The verification tests use the production Sigstore trust root and reject
modified payloads, subjects and source identities. This fixture verifies
publisher authentication. It is not a signed v2 distribution or evidence
that a prepared catalog has been activated.
