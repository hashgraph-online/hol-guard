# Installed command-pack release authority

Installed policy data is authenticated by the existing installed-package trust
boundary: both fixed-path native manifests bind the package version, source,
Root bytes and engine to the executing native binary. A request version, cache
hash or SQLite row cannot grant this authority. Rust rechecks these bindings.

Installed releases use the pinned `pep440_rs` implementation of PEP 440. The
64-byte input bound and three-component release segment remain in force.
Development, alpha, beta, release-candidate, final and post releases are ordered
by that implementation, including canonical aliases and epochs. Local version
labels are rejected: a local rebuild cannot advance public release authority.
Equivalent version spellings may retain the same identity; changing source,
Root, engine or security epochs at an equivalent version is rejected.

A strictly newer authenticated installed release authorizes its bundled source
and engine offline. This is package-release authority, not a claim about Git
ancestry. The installed profile neither publishes a remote Root nor updates the
protected remote source cursor. It retains the previous remote identity and all
authority/revocation high-water marks. Lower package versions and reused versions
with changed identities are rejected. Security epochs cannot decrease.

Remote publications retain separate two-component numeric counters. A changed
remote source still requires bounded compare evidence naming the exact protected
base, merge base and candidate head, ahead with zero commits behind. An installed
upgrade grants no remote ancestry proof, freshness, new remote trust or reset of
remote history. No network is required for an installed-only upgrade. Existing
selection and native pack-cache admission still apply in the new engine; external
packs require local opt-in, and the selected closure is prepared and committed
through the existing exact approval transaction. No expiry is fabricated.

## Legacy enrollment migration

Daemon installation/startup invokes migration under the existing exclusive
control-authority lease, before constructing the control API. Preview does not
provision or recreate a floor. Rust authenticates the retained credential-store
control anchor and its exact committed snapshot using the existing purpose keys,
then authenticates the installed release. It does not import arbitrary database
rows or reset/re-enroll controls. Local controls, managed state and saved command
approvals remain byte-for-byte unchanged.

Fresh enrollment and successful legacy migration write a separate scoped
credential-store enrollment stamp before writing/readback of the floor. Retained
floors are authenticated and preserved on repeated startup, including after SQLite
loss. A missing stamped floor, corrupt floor, wrong key, corrupt stamp or invalid
legacy anchor fails closed. Rolling back SQLite cannot remove the protected stamp.
An interrupted stamp-before-floor write therefore needs explicit recovery; startup
and preview never silently reconstruct it. This provides no hardware rollback
resistance against rollback of the entire credential store.

Legacy releases without pack activation migrate from their authenticated control
anchor. A pre-floor pack activation is deliberately rejected: its database header
alone is insufficient to establish protected remote history. Such a development
installation needs an authenticated recovery protocol before migration; this path
does not discard its activation or controls. A retained authenticated native floor
does not have this limitation. Full active-revocation quarantine and recovery of a
lost protected floor remain separate parent phases.
